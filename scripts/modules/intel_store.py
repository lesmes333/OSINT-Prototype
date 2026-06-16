#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Persistencia del grafo de inteligencia en SQLite (memoria entre escaneos).

Por qué: hasta ahora el grafo de entidades (entities.py) vivía SOLO en memoria;
al terminar el proceso se perdía y cada escaneo empezaba de cero. Sin memoria no
hay timeline, ni decay de confianza, ni "esto ya lo vi antes", ni monitorización
real. Este módulo guarda el grafo en un único fichero `intel.db` que SOBREVIVE
entre ejecuciones.

Importante:
  · SQLite viene incluido en Python (módulo `sqlite3` de la stdlib). NO es un
    servidor ni hay que instalar nada: es un fichero, igual que los JSON de
    outputs/. Cero dependencias nuevas.
  · Es ADITIVO y tolerante a fallos: si algo del .db falla, el escaneo sigue y
    se devuelve el grafo sin enriquecer (nunca rompe la generación de informes).

Modelo (mínimo y normalizado, base para timeline/decay/monitorización):
  entities      → un nodo por (tipo,valor), con first_seen/last_seen y nº de runs
  observations  → cada (entidad, fuente) con su primera/última vez vista
  relations     → aristas (origen)--rel-->(destino) con first_seen/last_seen

La clave estable de una entidad es sha1("tipo:valor"), así la misma entidad
vista en escaneos distintos (o en dominios distintos) se reconoce y fusiona.
"""

import hashlib
import os
import sqlite3
from typing import Optional

from .utils import get_logger

log = get_logger()

DB_FILENAME = "intel.db"


def entity_id(etype: str, value: str) -> str:
    """Clave estable de una entidad: sha1('tipo:valor'). Idempotente entre runs."""
    raw = f"{etype}:{value}".encode("utf-8", "replace")
    return hashlib.sha1(raw).hexdigest()


_SCHEMA = """
CREATE TABLE IF NOT EXISTS entities (
    id          TEXT PRIMARY KEY,
    type        TEXT NOT NULL,
    value       TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    best_grade  TEXT,
    runs        INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS observations (
    entity_id   TEXT NOT NULL,
    source      TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    count       INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (entity_id, source)
);
CREATE TABLE IF NOT EXISTS relations (
    from_id     TEXT NOT NULL,
    rel         TEXT NOT NULL,
    to_id       TEXT NOT NULL,
    source      TEXT,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    PRIMARY KEY (from_id, rel, to_id)
);
CREATE INDEX IF NOT EXISTS idx_entities_type  ON entities(type);
CREATE INDEX IF NOT EXISTS idx_entities_value ON entities(value);
CREATE INDEX IF NOT EXISTS idx_obs_entity     ON observations(entity_id);
"""

# Orden de grados para quedarnos con el "mejor" visto a lo largo del tiempo.
_GRADE_RANK = {"A": 0, "B": 1, "C": 2, "D": 3}


def _best_grade(a: Optional[str], b: Optional[str]) -> Optional[str]:
    """Devuelve el grado más alto (A>B>C>D) entre dos, tolerando None."""
    if not a:
        return b
    if not b:
        return a
    return a if _GRADE_RANK.get(a, 9) <= _GRADE_RANK.get(b, 9) else b


class IntelStore:
    """Almacén persistente del grafo. Úsese como context manager."""

    def __init__(self, output_dir: str):
        os.makedirs(output_dir, exist_ok=True)
        self.path = os.path.join(output_dir, DB_FILENAME)
        self.conn = sqlite3.connect(self.path)
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    # -- context manager -----------------------------------------------------
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def close(self):
        try:
            self.conn.close()
        except Exception:  # noqa: BLE001
            pass

    # -- núcleo: fusión + enriquecimiento ------------------------------------
    def merge_and_enrich(self, graph: dict, run_ts: str) -> dict:
        """
        Vuelca el grafo del escaneo actual al .db y ANOTA cada entidad con su
        histórico temporal. Devuelve el MISMO grafo enriquecido in-place con:

            entidad["first_seen"]  → primera vez que se vio (en cualquier escaneo)
            entidad["last_seen"]   → ahora (run_ts)
            entidad["is_new"]      → True si es la primera vez que aparece
            entidad["runs"]        → en cuántos escaneos ha aparecido

        Y en graph["stats"] añade:
            new_entities  → cuántas son nuevas en este escaneo
            seen_before   → cuántas ya se conocían

        Tolerante a fallos: ante cualquier error, devuelve el grafo sin tocar.
        """
        entidades = graph.get("entities") if isinstance(graph, dict) else None
        if not isinstance(entidades, list):
            return graph

        cur = self.conn.cursor()
        nuevas = recurrentes = 0

        for e in entidades:
            etype = str(e.get("type", ""))
            value = str(e.get("value", ""))
            if not etype or not value:
                continue
            eid = entity_id(etype, value)
            grade = e.get("grade")

            row = cur.execute(
                "SELECT first_seen, best_grade, runs FROM entities WHERE id=?",
                (eid,),
            ).fetchone()

            if row is None:  # primera vez que vemos esta entidad
                cur.execute(
                    "INSERT INTO entities (id, type, value, first_seen, last_seen, "
                    "best_grade, runs) VALUES (?,?,?,?,?,?,1)",
                    (eid, etype, value, run_ts, run_ts, grade),
                )
                e["first_seen"] = run_ts
                e["is_new"] = True
                e["runs"] = 1
                nuevas += 1
            else:  # ya conocida → conserva first_seen, suma un run
                first_seen, prev_grade, prev_runs = row
                merged_grade = _best_grade(prev_grade, grade)
                cur.execute(
                    "UPDATE entities SET last_seen=?, best_grade=?, runs=runs+1 "
                    "WHERE id=?",
                    (run_ts, merged_grade, eid),
                )
                e["first_seen"] = first_seen
                e["is_new"] = False
                e["runs"] = (prev_runs or 1) + 1
                recurrentes += 1

            e["last_seen"] = run_ts

            # Observaciones por fuente (para timeline/decay futuros).
            for src in e.get("sources", []) or []:
                self._upsert_observation(cur, eid, str(src), run_ts)

        # Relaciones (aristas) con su procedencia temporal.
        for r in graph.get("relations", []) or []:
            self._upsert_relation(cur, r, run_ts)

        self.conn.commit()

        st = graph.setdefault("stats", {})
        st["new_entities"] = nuevas
        st["seen_before"] = recurrentes
        return graph

    def _upsert_observation(self, cur, eid: str, source: str, run_ts: str) -> None:
        existing = cur.execute(
            "SELECT 1 FROM observations WHERE entity_id=? AND source=?",
            (eid, source),
        ).fetchone()
        if existing is None:
            cur.execute(
                "INSERT INTO observations (entity_id, source, first_seen, last_seen, "
                "count) VALUES (?,?,?,?,1)",
                (eid, source, run_ts, run_ts),
            )
        else:
            cur.execute(
                "UPDATE observations SET last_seen=?, count=count+1 "
                "WHERE entity_id=? AND source=?",
                (run_ts, eid, source),
            )

    def _upsert_relation(self, cur, rel: dict, run_ts: str) -> None:
        try:
            frm = rel.get("from", {})
            to = rel.get("to", {})
            from_id = entity_id(str(frm.get("type", "")), str(frm.get("value", "")))
            to_id = entity_id(str(to.get("type", "")), str(to.get("value", "")))
            relname = str(rel.get("rel", ""))
            if not relname:
                return
            existing = cur.execute(
                "SELECT 1 FROM relations WHERE from_id=? AND rel=? AND to_id=?",
                (from_id, relname, to_id),
            ).fetchone()
            if existing is None:
                cur.execute(
                    "INSERT INTO relations (from_id, rel, to_id, source, first_seen, "
                    "last_seen) VALUES (?,?,?,?,?,?)",
                    (from_id, relname, to_id, str(rel.get("source", "")), run_ts, run_ts),
                )
            else:
                cur.execute(
                    "UPDATE relations SET last_seen=? WHERE from_id=? AND rel=? AND to_id=?",
                    (run_ts, from_id, relname, to_id),
                )
        except Exception:  # noqa: BLE001 — una relación mal formada no debe abortar el volcado
            return


def persist_and_enrich(graph: dict, output_dir: str, run_ts: str) -> dict:
    """
    Punto de entrada cómodo para main.py. Abre el almacén, fusiona/enriquece y
    cierra. Si SQLite no estuviera disponible o fallara, registra un aviso y
    devuelve el grafo SIN enriquecer (el escaneo continúa con normalidad).
    """
    if not isinstance(graph, dict) or not graph.get("entities"):
        return graph
    try:
        with IntelStore(output_dir) as store:
            enriched = store.merge_and_enrich(graph, run_ts)
        st = enriched.get("stats", {})
        log.info(
            "   [*] Memoria de inteligencia: %d nuevas / %d ya conocidas (intel.db)",
            st.get("new_entities", 0), st.get("seen_before", 0),
        )
        return enriched
    except Exception as e:  # noqa: BLE001
        log.warning("   [!] No se pudo persistir en intel.db (se continúa sin memoria): %s", e)
        return graph
