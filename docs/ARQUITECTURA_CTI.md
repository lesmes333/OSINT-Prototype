# OSINT-Prototype → Plataforma de Inteligencia (CTI/OSINT)

> Diseño arquitectónico y estratégico para evolucionar la herramienta de
> *recon/scanner* a una **plataforma centrada en inteligencia**: entidades,
> grafo, correlación, workflows de investigación y monitorización.
>
> Principios no negociables: **defensivo, pasivo/no intrusivo, legal,
> open-source friendly, self-hostable y de bajo coste**. Nada de credenciales,
> captchas, login automation, crawling agresivo ni explotación.

---

## 0. Tesis central: de *scan-céntrico* a *entidad-céntrica*

Hoy el flujo es **acción → hallazgos → informe**:

```
escaneo(dominio) → dicts por fase → report.html
```

El problema no es la recolección (ya es buena). El problema es que **el
conocimiento muere con el informe**: cada escaneo es una isla, no hay memoria
entre ejecuciones, no hay relaciones persistentes, y "el mismo actor visto en
dos escaneos" no se detecta.

La evolución es invertir el centro de gravedad:

```
ENTIDAD (persistente) ←─ se enriquece con ─→ OBSERVACIONES (cada escaneo)
   │
   └─ vive en un GRAFO ─ se explora con PIVOTS ─ se agrupa en CASOS
```

Ya tienes la semilla correcta: `scripts/modules/entities.py` con `EntityGraph`,
`confidence_grade()` (A/B/C/D) y `source_tier()`. **Todo este diseño es la
continuación natural de ese módulo**, no un rediseño desde cero.

La regla de oro para no degenerar en "colección de scrapers": **toda nueva
capacidad debe responder a "¿qué entidad crea o qué relación añade?"**. Si la
respuesta es "ninguna, solo más datos sueltos", no entra.

---

## 1. ENTITY MODEL (modelo de entidades)

### 1.1 Anatomía de una entidad

Una entidad **no** es una fila de datos: es un nodo persistente con identidad,
procedencia y confianza. Modelo canónico (extensión de tu dict actual):

```
Entity {
  id            : hash estable = sha1(type + ":" + value_norm)   # clave global
  type          : email | dominio | subdominio | ip | asn | username |
                  telegram_channel | onion | wallet | hash | cve |
                  ransomware_group | leak | credencial | org | tech |
                  threat_actor | screenshot | fingerprint | pgp_key
  value         : valor normalizado (ya lo haces con _norm)
  attrs         : {} atributos tipados (estado onion, país IP, severidad CVE…)
  sources       : [(source, tier, first_seen, last_seen)]   # PROCEDENCIA
  grade         : A/B/C/D derivado (NO se almacena, se calcula)
  first_seen    : timestamp primera observación
  last_seen     : timestamp última observación
  tags          : [] etiquetas de analista (manual + automáticas)
  case_ids      : [] casos a los que pertenece
}
```

**Cambio clave frente a hoy:** las `sources` pasan de `(src, tier)` a incluir
**timestamps** (`first_seen`/`last_seen`). Sin tiempo no hay timeline, ni
"reapareció", ni decaimiento de confianza. Es la inversión de mayor ROI.

### 1.2 Identidad estable y el problema del `value` como clave

Hoy la clave es `(type, value_norm)`. Funciona, pero atarse al `value` literal
impide la **resolución de entidades** (sección 6): `john_doe` y `j0hn_doe` son
dos nodos distintos para siempre.

Diseño objetivo: **dos capas**.

- **Observación** (immutable, lo que viste): `(type, value, source, timestamp)`.
- **Entidad canónica** (mutable, lo que crees que es): agrupa N observaciones,
  posiblemente con valores distintos, bajo un `canonical_id`.

Esto desacopla "lo observado" de "lo inferido" y es lo que permite fusionar
alias sin perder la evidencia original (auditable, reversible).

### 1.3 Tipología por roles (no solo por tipo)

Más útil que una lista plana es clasificar entidades por **rol en la
investigación**, porque define cómo pivotas:

| Rol | Tipos | Para qué sirve |
|-----|-------|----------------|
| **Infraestructura** | dominio, subdominio, ip, asn, onion, fingerprint, tech | Mapear la superficie y reuso de infra |
| **Identidad** | email, username, telegram_channel, pgp_key, wallet | Vincular y resolver actores |
| **Artefacto** | hash, leak, credencial, screenshot | Evidencia material |
| **Amenaza** | cve, ransomware_group, threat_actor | Contexto de riesgo |
| **Contexto** | org, persona | Objetivo / víctima |

Los **pivots con más valor de inteligencia** cruzan roles: de Artefacto
(wallet repetida) a Identidad (mismo actor), de Infraestructura (favicon hash)
a Amenaza (misma campaña).

### 1.4 Cómo la nueva inteligencia expande el grafo

Cada hallazgo es un evento de expansión, y debe ser **idempotente** (reejecutar
no duplica) y **monótono en evidencia** (nunca borra procedencia, solo añade):

```
hallazgo nuevo →
  1. normalizar a (type, value)
  2. ¿existe entidad?  sí → merge sources + actualizar last_seen
                       no → crear entidad (first_seen = now)
  3. registrar relación(es) con su source
  4. recalcular grade (emergente, no almacenado)
  5. ¿dispara regla de correlación? → encolar pivot / alerta
```

Tu `EntityGraph.add()` ya hace 1–4 sin timestamps. El paso 5 (disparadores) es
lo que convierte la recolección en **inteligencia activa**.

---

## 2. GRAPH INTELLIGENCE (inteligencia de grafo)

### 2.1 Por qué grafo y no SQL

OSINT es topología: "qué conecta con qué" importa más que "cuántos hay". Las
preguntas reales son de **traversal**, no de agregación:

- "¿Qué otros dominios comparten este favicon/certificado/wallet?"
- "¿Hay un camino entre este email filtrado y aquel grupo de ransomware?"
- "¿Qué entidades están a ≤2 saltos de este .onion?"

En SQL eso son JOINs recursivos dolorosos; en grafo es traversal nativo.

### 2.2 Opciones de motor (todas open-source / self-host)

| Motor | Modelo | Pros | Contras | Recomendación |
|-------|--------|------|---------|---------------|
| **SQLite + tablas `nodes`/`edges`** | Grafo emulado | Cero infra, ya tienes ficheros JSON, embebido | Traversal manual, no escala a millones | **Empieza aquí (V2)** |
| **Neo4j Community** | Grafo nativo (Cypher) | Cypher expresivo, Bloom para viz, estándar de facto CTI | Java/JVM, RAM, Community sin clustering | **Objetivo V3** |
| **ArangoDB** | Multi-modelo (doc+grafo) | Un motor para doc+grafo+clave-valor, AQL | Menos ecosistema CTI, curva AQL | Alternativa si quieres doc store unificado |
| **Memgraph** | Grafo en memoria (Cypher) | Compatible Cypher, muy rápido, streaming | RAM-bound, menos maduro | Si priorizas velocidad sobre persistencia |
| **NetworkX (Python)** | Grafo en memoria | Cero infra, algoritmos (centralidad, comunidades) listos | No persiste, no concurrente | **Capa de análisis** sobre SQLite |

**Estrategia recomendada (pragmática y barata):**

1. **V2:** persistir el grafo en **SQLite** (`nodes`, `edges`, `observations`).
   Es un único fichero, encaja con tu modelo actual de outputs, y soporta
   millones de filas sin servidor.
2. **Análisis:** cargar el subgrafo relevante en **NetworkX** bajo demanda para
   métricas (centralidad, detección de comunidades = clustering de actores).
3. **V3:** cuando el volumen o las consultas lo justifiquen, **Neo4j Community**
   como motor de grafo "de verdad" + Cypher. Migración limpia desde SQLite
   porque el modelo nodo/arista ya está normalizado.

> Evita saltar a Neo4j el día 1: añade un servicio que mantener sin que el
> volumen lo justifique. SQLite + NetworkX cubre meses de evolución a coste 0.

### 2.3 Patrones de investigación sobre el grafo

- **Pivot** (1 salto): dado un nodo, expandir vecinos por tipo de relación.
- **Path-finding**: ¿existe cadena entre A y B? (víctima ↔ actor).
- **Vecindario a k-saltos**: contexto de una entidad (subgrafo ego).
- **Centralidad**: qué nodo es el "pegamento" (un wallet/PGP que conecta
  clústeres separados = candidato a pivote de actor).
- **Detección de comunidades** (Louvain/Leiden en NetworkX): clústeres densos =
  infraestructura/actor coherente. **Base de la correlación de actores (§13).**
- **Puntos de articulación**: nodos cuya eliminación parte el grafo = infra
  crítica de una campaña.

---

## 3. RELATIONSHIP MODELING (modelado de relaciones)

### 3.1 La arista como ciudadano de primera clase

Hoy una relación es `{from, rel, to, source}`. Para que sea inteligencia,
necesita los mismos atributos que una entidad:

```
Edge {
  from        : entity_id
  to          : entity_id
  rel         : tipo de relación (vocabulario CONTROLADO, ver abajo)
  source      : quién la afirma
  confidence  : qué tan firme es ESTA relación (no la entidad)
  first_seen  : cuándo se observó
  directed    : la dirección importa (resuelve_a) vs simétrica (comparte_infra)
}
```

**Punto crítico: confianza de la entidad ≠ confianza de la relación.** Un email
puede ser grado A (visto en 3 fuentes), pero "este email pertenece a este actor"
puede ser una inferencia débil. Separarlos evita el error CTI más común:
heredar certeza de los nodos a los enlaces.

### 3.2 Vocabulario controlado de relaciones

No dejes que cada módulo invente verbos (`menciona`, `asociado_a`,
`resuelve_a`… ya hay tres). Define un **diccionario cerrado** agrupado por
semántica:

| Categoría | Relaciones |
|-----------|------------|
| Estructural | `tiene_subdominio`, `resuelve_a`, `aloja_en` (ip→asn), `usa_tech` |
| Atribución | `pertenece_a`, `operado_por`, `alias_de`, `mismo_actor_que` |
| Co-ocurrencia | `aparece_con`, `menciona`, `comparte_infra`, `comparte_fingerprint` |
| Temporal/evento | `filtrado_en`, `publicado_por`, `víctima_de` |
| Derivada | `similar_a` (con score), `inferido_de` |

Un vocabulario cerrado es lo que permite consultas como "dame todas las
atribuciones de grado ≥B de este actor": imposible si cada módulo usa su jerga.

### 3.3 Relaciones derivadas vs observadas

- **Observadas**: vienen de una fuente (DNS dice A→IP). Alta fiabilidad estructural.
- **Derivadas**: las infiere el motor de correlación (`similar_a`,
  `mismo_actor_que`). Llevan **score + explicación** ("3 wallets compartidas +
  mismo estilo PGP"). Deben ser visualmente distinguibles (línea punteada) y
  filtrables, porque son hipótesis, no hechos.

---

## 4. INVESTIGATION WORKFLOWS (flujos de investigación)

### 4.1 El analista no "escanea": investiga en bucle

El flujo mental real de un analista CTI:

```
   PISTA  →  RECOLECTAR  →  NORMALIZAR  →  CORRELACIONAR  →  PIVOTAR
     ↑                                                          │
     └──────────────── nueva pista (hipótesis) ─────────────────┘
                              │
                        DOCUMENTAR (caso) → INFORME
```

Tu `--pivot` ya implementa el lazo recolectar→pivotar. Falta cerrar el resto:
normalizar al grafo (hecho), correlacionar (disparadores §1.4), documentar (caso §10).

### 4.2 Workflows concretos a soportar

1. **Triage de dominio** (lo que haces hoy): dominio → superficie + exposición.
2. **Expansión de actor**: dado un username/wallet/PGP, expandir a todo lo
   conectado a ≤2 saltos y puntuar la cohesión del clúster.
3. **Investigación de filtración**: dado un `leak`, ¿qué entidades nuestras
   aparecen? ¿qué grupo lo publicó? ¿reaparece infra conocida?
4. **Monitorización continua** (§12): no es un workflow puntual sino un
   *standing query* que dispara alertas.

### 4.3 Estado y reanudabilidad

Una investigación dura días. El workflow necesita **estado persistente**: qué
pivots ya se exploraron (no repetir), qué hipótesis están abiertas, qué quedó
pendiente. Esto vive en el **caso** (§10), no en una ejecución.

---

## 5. IOC CORRELATION (correlación de IOCs)

### 5.1 De "lista de IOCs" a "IOCs como nodos correlacionables"

Hoy `ioc_extractor` produce listas; `entities.add_iocs()` ya las vuelca al
grafo. El salto cualitativo es la **correlación cruzada**: un IOC vale por las
entidades que conecta, no por aparecer en una lista.

Reglas de correlación (disparadores del §1.4), de mayor a menor valor:

| Señal | Relación inferida | Por qué es fuerte |
|-------|-------------------|-------------------|
| Misma **wallet** en 2 contextos | `mismo_actor_que` | Las wallets son caras de rotar |
| Misma **clave PGP** | `mismo_actor_que` | Identidad criptográfica deliberada |
| Mismo **favicon hash** / **JARM** / **TLS cert** | `comparte_infra` | Reuso de infra entre dominios/.onion |
| Mismo **email/username** | `alias_de` / `pertenece_a` | Identidad reutilizada |
| Mismo **bloque IP / ASN** | `comparte_infra` (débil) | Puede ser hosting compartido |

### 5.2 El peso de la co-ocurrencia

Que dos IOCs aparezcan en el **mismo documento/hit** es señal. Que aparezcan
juntos **repetidamente en fuentes independientes** es señal fuerte. Modela la
co-ocurrencia como arista `aparece_con` con un contador; cuando supera umbral,
promociónala a una relación tipada. Esto reduce falsos positivos: una
co-aparición es ruido; veinte son patrón.

### 5.3 Enriquecimiento, no más recolección

La correlación se potencia enriqueciendo IOCs ya recolectados con APIs gratis
(passive, sin tocar al objetivo): geolocalización IP, ASN/BGP, reputación
(OTX/AbuseCH), edad de dominio (WHOIS), CT logs. Cada enriquecimiento añade
atributos o nodos, nunca un scraper nuevo "porque sí".

---

## 6. ENTITY RESOLUTION (resolución de entidades)

Es, como bien dices, **la pieza que falta más importante** para pasar de datos a
inteligencia. `john_doe` ≈ `j0hn_doe` ≈ `john-doe`.

### 6.1 Principio: nunca fusiones destructivamente

La resolución **propone**, no impone. Crea una entidad canónica que *agrupa*
observaciones, manteniendo cada observación original intacta y la fusión
**reversible y auditable** (con su score y motivo). Un falso merge que borra
evidencia es el peor error posible en CTI.

### 6.2 Heurísticas por tipo (de más fuerte a más débil)

**Señales fuertes (atribución casi determinista):**
- **Clave PGP idéntica** → mismo operador (identidad criptográfica).
- **Wallet reutilizada** → fuerte vínculo económico.
- **Fingerprint de infra** (favicon mmh3, JARM, hash de cert, hash de
  `index` HTML, ETag/Server banner) → reuso de infraestructura.

**Señales medias (requieren corroboración):**
- **Similitud de username**: normalización (leet→ascii: `0→o`,`1→i`,`3→e`,`@→a`),
  distancia de edición (Levenshtein/Jaro-Winkler), y **distancia en teclado**.
  `j0hn_doe`↔`john_doe` = 1 sustitución leet → score alto. `john`↔`johnny` =
  prefijo compartido → score medio.
- **Reuso de email/handle** entre plataformas.

**Señales débiles (solo suman, nunca atribuyen solas):**
- **Estilo de escritura** (stylometry): firmas, saludos, faltas recurrentes,
  emojis, husos horarios de actividad.
- **Patrón temporal**: misma franja horaria de publicación.

### 6.3 Modelo de scoring de fusión

No un umbral único, sino **evidencia acumulada ponderada**:

```
merge_score = Σ (peso_señal × fuerza_observada)

  PGP idéntico           : 0.95
  wallet compartida      : 0.85
  fingerprint infra      : 0.80
  username (leet/edit)   : 0.40
  email/handle reuso     : 0.50
  stylometry             : 0.20
  patrón temporal        : 0.10

  ≥0.90 → auto-merge (con log reversible)
  0.60–0.90 → SUGERIR al analista (cola de revisión)
  <0.60 → solo `similar_a` con score, sin fusionar
```

### 6.4 Riesgos operativos (críticos)

- **Reuso legítimo ≠ mismo actor**: hosting compartido, gateways de pago,
  servicios PGP públicos. Por eso `comparte_infra` débil **no** debe
  auto-promocionarse a `mismo_actor_que`.
- **Envenenamiento deliberado**: un actor puede plantar la wallet/PGP de otro
  para confundir. → nunca atribución por **una sola** señal fuerte sin
  corroboración independiente.
- **Colapso transitivo**: A≈B y B≈C no implica A≈C. Cuidado con fusiones en
  cadena que crean "súper-actores" falsos. Limita la transitividad y revisa
  clústeres grandes manualmente.

---

## 7. SOURCE RELIABILITY (fiabilidad de fuentes)

Ya tienes `source_tier()` (trusted/mixed/unknown/malicious). Profundicemos al
estándar CTI.

### 7.1 Adopta el Admiralty Code (NATO), estándar de inteligencia

Es el modelo canónico y separa dos ejes **independientes**:

- **Fiabilidad de la fuente** (A–F): histórico de acierto de la fuente.
- **Credibilidad de la información** (1–6): plausibilidad del dato concreto.

```
Fuente:   A=fiable siempre … C=bastante fiable … E=no fiable … F=desconocida
Info:     1=confirmada … 3=posiblemente cierta … 5=improbable … 6=no evaluable
```

Una pista es "B2", "C3", etc. Tu tier actual mapea bien al eje de fuente;
te falta el eje de **credibilidad del dato** (corroboración).

### 7.2 Fiabilidad dinámica, no estática

Hoy el tier es fijo por nombre de fuente. Mejóralo con **reputación que
aprende**: si una fuente acumula hallazgos que luego se confirman por otras, su
fiabilidad sube; si genera falsos positivos, baja. Empieza estático (lo que
tienes) y registra el histórico para hacerlo dinámico en V2/V3.

### 7.3 Independencia de fuentes (anti-eco)

Tres "fuentes" que se copian entre sí **no** son tres fuentes. Los agregadores
.onion republican lo mismo. Para que la corroboración cuente, las fuentes deben
ser **independientes**. Marca linaje de fuente (¿esta agrega a aquella?) y
descuenta corroboración entre fuentes no independientes. Es lo que evita que el
grade A se infle por eco.

---

## 8. CONFIDENCE SCORING (puntuación de confianza)

Tu `confidence_grade()` A/B/C/D ya es un buen punto de partida. Lo elevamos a un
modelo de inteligencia completo.

### 8.1 La confianza es multidimensional

Un único grado oculta información. Un finding maduro lleva **varias señales**:

```json
{
  "ioc": "example@test.com",
  "grade": "A",
  "confidence": 0.88,
  "dimensions": {
    "corroboration": 4,          // nº de fuentes INDEPENDIENTES
    "source_reliability": "B",   // mejor tier entre las fuentes (Admiralty)
    "recency_days": 5,           // antigüedad de la última observación
    "verified": true,            // ¿confirmado manualmente?
    "consistency": 0.9           // ¿las fuentes coinciden o se contradicen?
  },
  "first_seen": "2026-05-10",
  "last_seen": "2026-06-14"
}
```

### 8.2 Fórmula conceptual de confianza

```
confidence = f(corroboración, fiabilidad, consistencia) × decay(antigüedad)

  - corroboración: saturante (log), no lineal — la 5ª fuente aporta poco
  - fiabilidad: mejor tier independiente disponible
  - consistencia: penaliza fuentes que se contradicen
  - decay temporal: un IOC de hace 18 meses vale menos que uno de ayer
```

El **decay temporal** es clave y hoy no existe: la inteligencia caduca. Una
IP C2 de hace dos años probablemente ya no lo es. El decay convierte el grafo en
algo *vivo* y evita decisiones sobre datos muertos.

### 8.3 Reducción de falsos positivos

- **Allowlists**: CDNs, hosting compartido, rangos cloud, servicios PGP
  públicos → no atribuir, marcar como "infra compartida".
- **Corroboración independiente** obligatoria para promocionar a grado A.
- **Revisión humana** para findings de alto impacto (atribución de actor).
- **Feedback loop**: cuando el analista marca un FP, baja la reputación de la
  fuente y de la regla que lo generó (sección 7.2).

---

## 9. VISUAL GRAPH UI (visualización de grafo)

Aquí está el mayor salto de **valor percibido**: pasar de informe estático a
exploración interactiva. Pero hazlo por capas, sin reescribir todo.

### 9.1 Las tres capas de visualización

1. **Informe enriquecido (lo que tienes, mejorado)** — HTML/MD/JSON. Añade el
   resumen del grafo: top entidades por grado, clústeres, alertas. Coste bajo.
2. **Grafo embebido estático** — **PyVis** (genera un HTML standalone con
   vis.js): cero backend, abres el fichero y exploras/arrastras nodos. **Encaja
   perfecto con tu modelo actual de outputs HTML.** Es el siguiente paso obvio.
3. **App interactiva** — backend que sirve el grafo desde SQLite/Neo4j +
   **Cytoscape.js** en el front, con pivots en vivo, filtros y edición. Es V3+.

### 9.2 Comparativa de librerías (todas free)

| Librería | Tipo | Cuándo usarla | Esfuerzo |
|----------|------|---------------|----------|
| **PyVis** | Genera HTML standalone (vis.js) | **Ya**: grafo explorable sin servidor | Bajo |
| **Cytoscape.js** | JS interactivo, layouts pro, plugins | App de investigación seria | Medio-alto |
| **D3.js** | Bajo nivel, visualización a medida | Solo si necesitas algo muy custom | Alto |
| **Sigma.js / Graphology** | Renderizado WebGL para grafos grandes | Miles de nodos | Medio |

**Recomendación:** **PyVis en V2** (ROI inmediato, encaja con `report.py`),
**Cytoscape.js en V3** cuando tengas backend de grafo.

### 9.3 Qué espera ver un analista (UX de investigación)

- **Codificación visual**: forma/icono = tipo de entidad; color = grado de
  confianza (A verde→D gris); grosor de arista = fuerza; línea punteada =
  relación inferida (§3.3).
- **Pivote con un clic**: clic en nodo → expandir vecinos sin recargar.
- **Filtros**: por tipo, por grado mínimo, por ventana temporal, por caso.
- **Foco + contexto**: vecindario ego del nodo seleccionado, resto atenuado.
- **Detalle al seleccionar**: panel con fuentes, timestamps, atributos, notas.
- **Layouts**: force-directed por defecto; jerárquico para infra; temporal para
  evolución.

> Anti-patrón: el "hairball" (bola de pelo) de 5.000 nodos. La UI debe partir de
> un nodo o caso y expandir bajo demanda, nunca volcar el grafo entero.

---

## 10. CASE MANAGEMENT (gestión de casos)

El **contenedor que da continuidad** a la investigación. `CASE-2026-001`.

### 10.1 Anatomía de un caso

```
Case {
  id           : CASE-2026-001
  title, status: open | active | monitoring | closed
  priority, tlp: TLP:CLEAR/GREEN/AMBER/RED   (manejo de info)
  hypotheses   : [] hipótesis abiertas/confirmadas/descartadas
  entities     : [] entidades vinculadas (referencia al grafo, no copia)
  evidence     : [] artefactos (screenshots, ficheros, hashes, capturas)
  notes        : [] notas de analista (markdown, fechadas, atribuidas)
  tags         : []
  timeline     : [] eventos (auto + manuales)
  tasks        : [] pendientes / pivots no explorados
  audit_log    : [] quién hizo qué y cuándo (cadena de custodia)
}
```

### 10.2 Principios de un caso serio

- **El caso referencia el grafo, no lo copia**: una entidad puede estar en
  varios casos; la verdad vive en el grafo, el caso es una vista + anotaciones.
- **Cadena de custodia**: todo cambio se registra (audit log). Es lo que separa
  una herramienta de juguete de una usable en un contexto formal.
- **Evidencia inmutable**: las capturas/artefactos se guardan con su hash y
  timestamp; nunca se editan, se versionan.
- **Hipótesis explícitas**: documentar lo que *crees* (y su estado) evita el
  sesgo de confirmación y hace la investigación auditable por un tercero.

### 10.3 Implementación pragmática

Empieza simple: un caso = directorio + `case.json` + carpeta `evidence/`. Reusa
tu estructura de `outputs/`. No necesitas base de datos para esto en V2; el
grafo en SQLite y los casos en JSON conviven bien.

---

## 11. TIMELINE ANALYSIS (análisis temporal)

Imposible sin los `timestamps` del §1.1: esta sección es la justificación de por
qué ese cambio es prioritario.

### 11.1 Dos ejes temporales (no confundir)

- **Tiempo de observación** (cuándo lo *vimos*): dirige el monitoring y el decay.
- **Tiempo del evento** (cuándo *ocurrió*: fecha de la filtración, registro del
  dominio, publicación del post): dirige la narrativa de la investigación.

Modela ambos. Confundirlos lleva a conclusiones falsas ("apareció hoy" cuando el
evento es de hace un año).

### 11.2 Qué habilita el timeline

- **Narrativa del caso**: reconstruir la secuencia de una campaña.
- **Detección de cambios**: ya tienes `diffing.py`; el timeline lo generaliza a
  "qué cambió en esta entidad entre observaciones".
- **Correlación temporal**: entidades que aparecen/cambian juntas en el tiempo →
  señal de relación (§6.2, patrón temporal).
- **Decay de confianza** (§8.2): la antigüedad alimenta el scoring.
- **Detección de patrones**: franjas horarias de actividad de un actor (pista de
  huso horario / atribución débil).

### 11.3 Visualización

Línea temporal por entidad o por caso (mismo PyVis/Cytoscape con layout
temporal, o una librería ligera tipo vis-timeline). Cada evento enlaza a la
entidad/observación que lo originó.

---

## 12. MONITORING WORKFLOWS (flujos de monitorización)

De "escaneo puntual" a **vigilancia continua**. Ya tienes `diffing.py` (diff
entre escaneos): es la base, falta convertirlo en *standing queries* + alertas.

### 12.1 El modelo: watchlist → observación → diff → alerta

```
WATCHLIST (entidades/queries que vigilo)
   │  (programado: cron / systemd timer)
   ▼
OBSERVAR (reejecutar recolección sobre la watchlist)
   │
   ▼
DIFF contra estado previo del grafo (diffing.py generalizado)
   │
   ▼
EVALUAR REGLAS → ¿cruza umbral? → ALERTA (con contexto del grafo)
```

### 12.2 Tipos de alerta de valor

- **Nueva aparición**: tu dominio/email/marca aparece en una nueva filtración o
  canal Telegram.
- **Reaparición de infra conocida**: un favicon/PGP/wallet ya catalogado vuelve
  a verse en sitio nuevo → posible nueva campaña del mismo actor.
- **Cambio de estado**: un .onion catalogado cae o vuelve (ya tienes
  `onion_health`); un grupo de ransomware publica nueva víctima.
- **Cambio de confianza**: un finding sube a grado A (corroborado) → ahora es
  accionable.

### 12.3 Diseño anti-ruido (lo que hace o rompe el monitoring)

- **Deduplicación de alertas**: no alertar dos veces de lo mismo (estado, no
  evento aislado).
- **Umbrales y agrupación**: agrupar alertas relacionadas en un "incidente".
- **TLP y enrutado**: a quién/cómo notificar (fichero, webhook, email).
- El monitoring que genera demasiado ruido se ignora; el diseño de
  supresión/agrupación es tan importante como la detección.

---

## 13. SEMANTIC CORRELATION (correlación semántica)

Correlación más allá de matches exactos: "esto *se parece* a aquello". Aquí van
embeddings y similitud, **todo local y gratis**.

### 13.1 Tres familias de similitud

| Familia | Técnica (local/free) | Detecta |
|---------|----------------------|---------|
| **Texto** (notas ransomware, posts, anuncios) | Embeddings con `sentence-transformers` (modelo local, p.ej. MiniLM) + similitud coseno | Notas de rescate reescritas, mismo redactor, plantillas reutilizadas |
| **Estructura HTML** | Hash estructural del DOM, shingling/SimHash, tree-edit aprox. | Sitios de leak clonados, mismo kit/plantilla |
| **Imagen** (screenshots, logos) | Perceptual hash (pHash/dHash), o embeddings CLIP locales | Paneles de leak con mismo layout, logos reusados |

### 13.2 Por qué embeddings locales y no API

- **Coste/privacidad**: `sentence-transformers` corre en CPU, sin enviar datos
  sensibles a terceros. Coherente con tu principio self-host/low-cost.
- **Suficiente**: para *clustering de similitud* (no generación) un MiniLM local
  rinde de sobra.
- **Almacenamiento de vectores**: empieza con cálculo en memoria
  (numpy/`scikit-learn`); si crece, **sqlite-vec** o **FAISS** (ambos
  embebidos, gratis) antes que una vector-DB con servidor.

### 13.3 De similitud a clúster de actor

```
embeddings/hashes → similitud por pares → aristas `similar_a` (con score)
   → añadir al grafo → detección de comunidades (Louvain, §2.3)
   → clúster denso = candidato a "mismo actor / misma campaña"
   → SUGERIR al analista (nunca atribución automática, §6.4)
```

La correlación semántica **alimenta** la resolución de entidades (§6) y el
scoring (§8): es una señal más, ponderada, no una verdad.

### 13.4 Riesgos

- **Plantillas compartidas ≠ mismo actor**: muchos grupos usan los mismos kits
  RaaS. La similitud de nota indica *familia*, no necesariamente *operador*.
- **Falsos positivos de pHash**: imágenes genéricas (banderas, iconos comunes)
  → allowlist visual.

---

## 14. INTELLIGENCE PIPELINES (tuberías de inteligencia)

La arquitectura que une todo lo anterior en un flujo coherente y reejecutable.

### 14.1 El pipeline canónico CTI

```
COLLECT → NORMALIZE → ENRICH → CORRELATE → SCORE → STORE → ALERT/REPORT
 (tienes)  (entities)  (APIs)   (§5,§13)   (§8)   (SQLite)  (§9,§12)
```

Cada etapa es **idempotente y desacoplada**: re-correr ENRICH no re-COLLECTa;
añadir una regla en CORRELATE no toca COLLECT. Tus módulos actuales ya están
bien separados; esto les pone un espinazo común (el grafo) entre etapas.

### 14.2 De dicts a un bus de eventos interno

Hoy las fases se pasan dicts. El modelo objetivo: cada etapa **emite
observaciones** al grafo, y los **disparadores** (§1.4) reaccionan. Esto
desacopla productores de consumidores y permite añadir correlaciones sin tocar
la recolección. No necesitas Kafka: una cola en proceso o una tabla `events` en
SQLite basta para empezar.

### 14.3 Estandariza la salida en STIX 2.1 (interoperabilidad)

Para no quedar aislado: **STIX 2.1** es el lenguaje común de CTI (entidades =
*SDOs*, relaciones = *SROs*). Exportar/importar STIX te permite alimentar/leer
**OpenCTI**, **MISP**, etc. No reinventes el modelo de datos: alinéate con STIX
desde V2 (tu modelo de entidades ya es casi isomorfo).

> Decisión estratégica: ¿construir tu propia plataforma o convertirte en un
> **colector/enriquecedor que alimenta OpenCTI/MISP**? Ambos son válidos. El
> camino barato es: tu herramienta hace lo que hace bien (recolección
> dark web + correlación), exporta STIX, y deja la viz/gestión pesada a OpenCTI
> si algún día lo necesitas. Mantén la puerta abierta.

---

## 15. FUTURE AI-ASSISTED ANALYSIS (análisis asistido por IA)

La IA va **al final** por una razón: sin el grafo, los embeddings y el scoring,
un LLM solo añade alucinaciones bonitas. Con ellos, multiplica al analista.

### 15.1 Dónde la IA aporta valor real (y dónde no)

| Caso de uso | Valor | Riesgo |
|-------------|-------|--------|
| **Resumen de hallazgos** (caso → narrativa legible) | Alto | Bajo (texto, revisable) |
| **Triage/priorización** (qué findings mirar primero) | Alto | Medio (sesgo) |
| **Extracción de IOCs de texto no estructurado** (NER) | Alto | Bajo |
| **Sugerir pivots/hipótesis** ("mira esta conexión") | Medio | Medio |
| **Explicar un clúster** ("por qué estas entidades parecen el mismo actor") | Alto | Medio |
| **Atribución automática** | ❌ NO | Crítico (alucinación + sesgo) |

### 15.2 Principio rector: RAG sobre el grafo, IA aumentada por evidencia

La IA **nunca inventa inteligencia**; opera sobre lo que el grafo ya contiene:

```
pregunta del analista → recuperar subgrafo/evidencia relevante (RAG)
   → LLM razona SOLO sobre esa evidencia → respuesta CON CITAS a entidades/fuentes
   → el analista verifica contra el grafo
```

Toda salida de IA debe ser **trazable a entidades y fuentes concretas** (citas),
y marcada como "generado por IA, sin verificar". La IA es un grado D hasta que un
humano la promociona.

### 15.3 Opciones técnicas (coherentes con free/self-host)

- **Local**: Ollama + modelos abiertos (Llama/Mistral/Qwen) para resumen y NER
  sin coste por token ni fuga de datos. Encaja con tu principio de privacidad.
- **API**: para tareas que exijan más capacidad, la API de Claude (modelos
  recientes) con **prompt caching** del contexto del grafo para abaratar.
  Mantén los datos sensibles en local y manda solo lo necesario.
- **Híbrido**: NER/resumen en local; razonamiento complejo bajo demanda en API.

---

## ROADMAP (V1 → V5)

Priorizado por **ROI de inteligencia / esfuerzo**, no por vistosidad.

### V1 — Estado actual ✅
Recolección fuerte: subdominios, DNS/WHOIS/threat intel, CVE/exploits, INCIBE,
dark web (Tor), ransomware leaks, Telegram, IOC extraction, onion crawling,
reporting, diffing, OPSEC. **Semilla de entidades ya creada** (`entities.py`).

### V2 — Capa de inteligencia (PERSISTENCIA + CONFIANZA) — *prioridad máxima*
El salto de mayor ROI. Hace que el conocimiento **sobreviva al escaneo**.
1. **Timestamps** en observaciones (`first_seen`/`last_seen`). *(habilita §11,§8)*
2. **Persistencia en SQLite** (`nodes`/`edges`/`observations`). Grafo entre runs.
3. **Confidence scoring completo** (multidimensional + decay temporal, §8).
4. **Fiabilidad de fuentes** Admiralty + independencia anti-eco (§7).
5. **Visualización PyVis** embebida en el informe (§9.2). *Ganancia visible ya.*
6. **Casos básicos** (directorio + `case.json` + evidencia, §10.3).
> *No hacer aún:* Neo4j, app web, IA. Tradeoff: persistencia > vistosidad.

### V3 — Inteligencia de grafo (PIVOTS + RESOLUCIÓN)
1. **Resolución de entidades** (§6): heurísticas + scoring de fusión reversible.
2. **Correlación de IOCs** por reglas (wallet/PGP/fingerprint, §5).
3. **NetworkX** para centralidad y detección de comunidades (§2.3).
4. **(Opcional) Neo4j Community** si el volumen/consultas lo justifican.
5. **App de grafo interactiva** (Cytoscape.js) si los casos lo piden.
6. **Monitorización con watchlists + alertas** (§12).

### V4 — Correlación semántica (SIMILITUD + CLUSTERING)
1. **Embeddings locales** de texto (sentence-transformers) para notas/posts.
2. **Hashing perceptual** de screenshots + **fingerprints de infra** (§13).
3. **Clustering de actores** vía comunidades sobre aristas `similar_a`.
4. **Vector store embebido** (sqlite-vec/FAISS) si crece el volumen.

### V5 — Investigación asistida por IA
1. **Resumen de casos** y narrativas (local Ollama / API con caching).
2. **NER** para extracción de IOCs de texto libre.
3. **RAG sobre el grafo** con respuestas citadas y verificables (§15.2).
4. **Sugerencia de pivots/hipótesis** (siempre como grado D revisable).

### Qué NO hacer (anti-objetivos)
- ❌ Añadir cientos de APIs/scrapers "por cubrir más" → caos de fuentes.
- ❌ Crawling agresivo, captchas, login, credenciales → fuera del marco legal/ético.
- ❌ Atribución automática de actores sin humano → riesgo CTI inaceptable.
- ❌ Saltar a Neo4j/app web/IA antes de tener persistencia + confianza (V2).
- ❌ Vector-DB o Kafka con servidor cuando SQLite/FAISS embebido sobra.
- ❌ Feature bloat: toda función debe crear una entidad o una relación.

---

## Resumen ejecutivo en una frase

> El proyecto ya **recolecta** bien; el siguiente salto no es recolectar más,
> sino **recordar, relacionar, puntuar y razonar**: persistir el grafo de
> entidades con tiempo y confianza (V2), pivotar y resolver actores (V3),
> correlacionar por similitud (V4) y asistir con IA trazable (V5) —
> manteniéndolo siempre defensivo, pasivo, legal y de bajo coste.

### El primer paso concreto (si solo haces una cosa)
Añadir **timestamps + persistencia SQLite** al `EntityGraph` actual. Es el
cambio que desbloquea timeline, decay, monitorización y memoria entre escaneos —
y es una extensión directa de `entities.py`, no una reescritura.

