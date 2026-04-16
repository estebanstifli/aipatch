# WordPress Abilities API - Guía para Desarrolladores

## ¿Qué es la Abilities API?

La Abilities API de WordPress 6.9+ es un registro centralizado de capacidades (abilities) que expone funcionalidades de plugins/temas en un formato estandarizado, legible tanto por humanos como por máquinas (agentes de IA).

**Objetivo**: Permitir que código PHP, agentes de IA, o cualquier cliente pueda:
1. **Descubrir** qué abilities están disponibles
2. **Inspeccionar** sus schemas de entrada/salida
3. **Ejecutar** abilities de forma programática

---

## Arquitectura

```
┌─────────────────────────────────────────────────────────────┐
│                    WordPress Core                            │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              Abilities Registry                      │    │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐   │    │
│  │  │ core/       │ │ allsi/      │ │ myplugin/   │   │    │
│  │  │ get-site-   │ │ search-     │ │ my-ability  │   │    │
│  │  │ info        │ │ image       │ │             │   │    │
│  │  └─────────────┘ └─────────────┘ └─────────────┘   │    │
│  └─────────────────────────────────────────────────────┘    │
│                           │                                  │
│              ┌────────────┴────────────┐                    │
│              ▼                         ▼                    │
│     REST API Endpoint          PHP Functions                │
│   /wp-abilities/v1/          wp_get_abilities()            │
│                              wp_run_ability()               │
└─────────────────────────────────────────────────────────────┘
```

---

## Cómo se Define y Registra una Ability (Implementación real en este plugin)

En All Sources Images, el registro real se hace en `includes/class-allsi-abilities.php` y se carga desde `all-sources-images.php`.

### Flujo real de registro

1. `all-sources-images.php` carga el archivo de abilities:
   - `require plugin_dir_path( __FILE__ ) . 'includes/class-allsi-abilities.php';`

2. Al cargarse `includes/class-allsi-abilities.php`, se auto-inicializa:
   - `ALLSI_abilities_init();`

3. El constructor de `ALLSI_Abilities` conecta los hooks oficiales:
   - `add_action( 'wp_abilities_api_categories_init', array( $this, 'register_categories' ) );`
   - `add_action( 'wp_abilities_api_init', array( $this, 'register_abilities' ) );`

4. `register_categories()` registra la categoría (`media`) con `wp_register_ability_category()`.

5. `register_abilities()` llama a métodos por ability (`register_search_image_ability()`, `register_set_featured_image_ability()`, etc.).

6. Cada método usa `wp_register_ability( 'namespace/ability-name', array( ... ) )` con:
   - `label`, `description`, `category`
   - `input_schema`, `output_schema`
   - `execute_callback`, `permission_callback`
   - `meta` (incluyendo `show_in_rest` y `mcp.public`)

### Ejemplo real (resumido) de este plugin

```php
$result = wp_register_ability(
    'allsi/generate-ai-image',
    array(
        'label'       => __( 'Generate AI Image', 'all-sources-images' ),
        'category'    => 'media',
        'input_schema' => array(
            'type'       => 'object',
            'properties' => array(
                'prompt' => array( 'type' => 'string' ),
                'source' => array( 'type' => 'string' ),
            ),
            'required' => array( 'prompt' ),
        ),
        'execute_callback'    => array( $this, 'execute_generate_ai_image' ),
        'permission_callback' => array( $this, 'can_edit_posts' ),
        'meta'                => array(
            'show_in_rest' => true,
            'mcp'          => array( 'public' => true, 'type' => 'tool' ),
        ),
    )
);
```

### Checklist mínima para que quede disponible

1. Cargar el archivo que registra abilities antes de que termine el ciclo de carga del plugin.
2. Conectar `register_abilities()` a `wp_abilities_api_init`.
3. Registrar categoría primero (`wp_abilities_api_categories_init`) si usas categoría custom.
4. Definir `permission_callback` válido (si falla permisos, no se podrá ejecutar).
5. Activar `meta.show_in_rest = true` para exponerla por REST.

---

## Funciones PHP Principales

### 1. Descubrir Abilities Disponibles

```php
<?php
/**
 * Obtener todas las abilities registradas
 */
function mi_plugin_listar_abilities() {
    // Obtener el registro de abilities
    $registry = wp_get_ability_registry();
    
    if ( ! $registry ) {
        return array();
    }
    
    // Obtener todas las abilities
    $abilities = $registry->get_all();
    
    $lista = array();
    foreach ( $abilities as $name => $ability ) {
        $lista[] = array(
            'name'        => $name,
            'label'       => $ability->get_label(),
            'description' => $ability->get_description(),
            'category'    => $ability->get_category(),
        );
    }
    
    return $lista;
}

// Uso:
$abilities = mi_plugin_listar_abilities();
foreach ( $abilities as $ability ) {
    echo "- {$ability['name']}: {$ability['label']}\n";
}
```

### 2. Obtener Información de una Ability Específica

```php
<?php
/**
 * Obtener detalles de una ability específica
 */
function mi_plugin_obtener_ability( $ability_name ) {
    $registry = wp_get_ability_registry();
    
    if ( ! $registry ) {
        return null;
    }
    
    $ability = $registry->get( $ability_name );
    
    if ( ! $ability ) {
        return null;
    }
    
    return array(
        'name'          => $ability_name,
        'label'         => $ability->get_label(),
        'description'   => $ability->get_description(),
        'category'      => $ability->get_category(),
        'input_schema'  => $ability->get_input_schema(),
        'output_schema' => $ability->get_output_schema(),
    );
}

// Uso:
$info = mi_plugin_obtener_ability( 'allsi/search-image' );
if ( $info ) {
    echo "Ability: {$info['label']}\n";
    echo "Descripción: {$info['description']}\n";
    echo "Input Schema: " . json_encode( $info['input_schema'], JSON_PRETTY_PRINT ) . "\n";
}
```

### 3. Ejecutar una Ability

```php
<?php
/**
 * Ejecutar una ability con parámetros
 */
function mi_plugin_ejecutar_ability( $ability_name, $input = array() ) {
    $registry = wp_get_ability_registry();
    
    if ( ! $registry ) {
        return new WP_Error( 'no_registry', 'Abilities registry not available' );
    }
    
    $ability = $registry->get( $ability_name );
    
    if ( ! $ability ) {
        return new WP_Error( 'not_found', "Ability '{$ability_name}' not found" );
    }
    
    // Verificar permisos
    if ( ! $ability->check_permission() ) {
        return new WP_Error( 'permission_denied', 'You do not have permission to run this ability' );
    }
    
    // Ejecutar la ability
    $result = $ability->run( $input );
    
    return $result;
}

// Uso - Buscar imágenes:
$resultado = mi_plugin_ejecutar_ability( 'allsi/search-image', array(
    'search_term' => 'sunset beach',
    'source'      => 'pexels',
    'count'       => 3,
) );

if ( is_wp_error( $resultado ) ) {
    echo "Error: " . $resultado->get_error_message();
} else {
    foreach ( $resultado['images'] as $image ) {
        echo "- {$image['url']}\n";
    }
}
```

---

## Ejemplos Prácticos

### Ejemplo 1: Buscar y Establecer Imagen Destacada

```php
<?php
/**
 * Buscar una imagen y establecerla como featured image de un post
 */
function mi_plugin_auto_imagen_destacada( $post_id, $search_term, $source = 'pixabay' ) {
    // Paso 1: Buscar imagen
    $search_result = mi_plugin_ejecutar_ability( 'allsi/search-image', array(
        'search_term' => $search_term,
        'source'      => $source,
        'count'       => 1,
    ) );
    
    if ( is_wp_error( $search_result ) || empty( $search_result['images'] ) ) {
        return new WP_Error( 'no_images', 'No se encontraron imágenes' );
    }
    
    $image_url = $search_result['images'][0]['url'];
    $alt_text  = $search_result['images'][0]['alt'];
    $caption   = $search_result['images'][0]['caption'];
    
    // Paso 2: Establecer como featured image
    $set_result = mi_plugin_ejecutar_ability( 'allsi/set-featured-image', array(
        'post_id'   => $post_id,
        'image_url' => $image_url,
        'alt_text'  => $alt_text,
        'caption'   => $caption,
    ) );
    
    return $set_result;
}

// Uso:
$resultado = mi_plugin_auto_imagen_destacada( 123, 'mountain landscape', 'pexels' );
if ( ! is_wp_error( $resultado ) && $resultado['success'] ) {
    echo "Imagen establecida! Attachment ID: {$resultado['attachment_id']}";
}
```

### Ejemplo 2: Generar Imagen con IA e Insertarla en Contenido

```php
<?php
/**
 * Generar imagen con IA e insertarla en el contenido del post
 */
function mi_plugin_generar_e_insertar( $post_id, $prompt, $ai_source = 'dallev1' ) {
    // Paso 1: Generar imagen con IA
    $generate_result = mi_plugin_ejecutar_ability( 'allsi/generate-ai-image', array(
        'prompt' => $prompt,
        'source' => $ai_source,
        'size'   => '1024x1024',
    ) );
    
    if ( is_wp_error( $generate_result ) || ! $generate_result['success'] ) {
        return new WP_Error( 'generation_failed', 'No se pudo generar la imagen' );
    }
    
    $image_url = $generate_result['url'];
    
    // Paso 2: Insertar en contenido después del primer párrafo
    $insert_result = mi_plugin_ejecutar_ability( 'allsi/insert-image-in-content', array(
        'post_id'   => $post_id,
        'image_url' => $image_url,
        'position'  => 1,
        'placement' => 'after',
        'element'   => 'p',
        'alt_text'  => $prompt,
    ) );
    
    return $insert_result;
}

// Uso:
$resultado = mi_plugin_generar_e_insertar( 
    456, 
    'A futuristic city with flying cars at sunset',
    'dallev1'
);
```

### Ejemplo 3: Descubrir Abilities por Categoría

```php
<?php
/**
 * Obtener abilities filtradas por categoría
 */
function mi_plugin_abilities_por_categoria( $categoria ) {
    $registry = wp_get_ability_registry();
    
    if ( ! $registry ) {
        return array();
    }
    
    $todas = $registry->get_all();
    $filtradas = array();
    
    foreach ( $todas as $name => $ability ) {
        if ( $ability->get_category() === $categoria ) {
            $filtradas[ $name ] = array(
                'label'       => $ability->get_label(),
                'description' => $ability->get_description(),
            );
        }
    }
    
    return $filtradas;
}

// Obtener todas las abilities de la categoría "media"
$media_abilities = mi_plugin_abilities_por_categoria( 'media' );
foreach ( $media_abilities as $name => $info ) {
    echo "{$name}: {$info['label']}\n";
}

// Resultado esperado:
// allsi/search-image: Search Images
// allsi/set-featured-image: Set Featured Image
// allsi/auto-generate-for-post: Auto Generate Image for Post
// allsi/insert-image-in-content: Insert Image in Post Content
// allsi/generate-ai-image: Generate AI Image
```

---

## Acceso via REST API

Las abilities también están disponibles via REST API:

### Listar Abilities

```bash
GET /wp-json/wp-abilities/v1/abilities

# O con permalinks desactivados:
GET /?rest_route=/wp-abilities/v1/abilities
```

### Obtener Información de una Ability

```bash
GET /wp-json/wp-abilities/v1/abilities/allsi/search-image
```

### Ejecutar una Ability

```bash
POST /wp-json/wp-abilities/v1/abilities/allsi/search-image/run
Content-Type: application/json
Authorization: Basic <base64_credentials>

{
  "input": {
    "search_term": "sunset beach",
    "source": "pexels",
    "count": 3
  }
}
```

---

## Verificar si Abilities API está Disponible

```php
<?php
/**
 * Verificar si la Abilities API está disponible (WordPress 6.9+)
 */
function mi_plugin_abilities_disponible() {
    return function_exists( 'wp_get_ability_registry' );
}

// Uso seguro:
if ( mi_plugin_abilities_disponible() ) {
    // Usar Abilities API
    $resultado = mi_plugin_ejecutar_ability( 'allsi/search-image', array( ... ) );
} else {
    // Fallback para versiones anteriores de WordPress
    // o llamar directamente a las funciones del plugin
}
```

---

## Abilities de All Sources Images Disponibles

| Ability | Descripción | Parámetros Principales |
|---------|-------------|------------------------|
| `allsi/search-image` | Buscar imágenes en stock o AI | `search_term`, `source`, `count` |
| `allsi/set-featured-image` | Establecer imagen destacada | `post_id`, `image_url` |
| `allsi/auto-generate-for-post` | Auto-generar imagen para post | `post_id`, `source`, `overwrite` |
| `allsi/insert-image-in-content` | Insertar imagen en contenido | `post_id`, `image_url`, `position` |
| `allsi/generate-ai-image` | Generar imagen con IA | `prompt`, `source`, `size` |

### Sources Disponibles

**Stock Photos:**
- `pixabay` - Gratis, gran biblioteca (default)
- `pexels` - Alta calidad, gratis
- `unsplash` - Fotos artísticas
- `flickr` - Contenido diverso
- `openverse` - Creative Commons
- `giphy` - GIFs animados

**AI Generators:**
- `dallev1` - OpenAI DALL-E 3
- `stability` - Stable Diffusion
- `gemini` - Google Gemini
- `replicate` - Varios modelos de IA
- `workers_ai` - Cloudflare AI

---

## Notas Importantes

1. **Permisos**: Cada ability verifica permisos antes de ejecutar. El usuario debe tener `edit_posts` o el permiso específico de la ability.

2. **MCP Integration**: Para exponer abilities a agentes de IA externos (Claude, GPT, etc.), se requiere el plugin MCP Adapter y añadir `'mcp' => array('public' => true)` en el meta de la ability.

3. **Validación**: Las abilities validan los inputs según su `input_schema`. Parámetros inválidos retornan `WP_Error`.

4. **URLs Temporales**: Las imágenes generadas con IA tienen URLs temporales (~1 hora). Usa `allsi/set-featured-image` para guardarlas permanentemente.

5. **API Keys**: Los sources de IA requieren API keys configuradas en los ajustes del plugin.

---

## Implementacion aplicada en Aipatch Security Scanner (abril 2026)

Esta guia ahora incluye una implementacion real para el plugin Aipatch Security Scanner, orientada a uso por agentes IA externos via MCP y Abilities API.

### Objetivo de diseno

- Priorizar abilities de lectura (read-only)
- Devolver datos estructurados para que un agente IA pueda razonar y priorizar
- Permitir auditoria completa del sitio y triage de ficheros sospechosos

### Abilities registradas

| Ability | Tipo | Descripcion |
|---------|------|-------------|
| `aipatch/audit-site` | Lectura | Ejecuta auditoria completa y devuelve informe estructurado |
| `aipatch/audit-suspicious` | Lectura | Busca ficheros sospechosos por heuristica local |
| `aipatch/get-async-job-status` | Lectura | Consulta estado y resultado de jobs asincronos |

### Input de `aipatch/audit-site`

```json
{
    "input": {
        "refresh_scan": true,
        "include_dismissed": false,
        "include_vulnerabilities": true,
        "include_summary": true,
        "async": true
    }
}
```

### Output esperado de `aipatch/audit-site` en modo async

```json
{
    "success": true,
    "async": true,
    "job_id": "f0f34b26-7bb1-497f-b60d-52e4f7c31c09",
    "status": "queued",
    "job_type": "audit-site",
    "created_at_gmt": "2026-04-16T11:30:00+00:00",
    "poll_ability": "aipatch/get-async-job-status"
}
```

### Output esperado de `aipatch/audit-site` en modo sync (resumen)

```json
{
    "success": true,
    "generated_at_gmt": "2026-04-16T11:30:00+00:00",
    "scan_mode": "fresh",
    "score": 82,
    "issues_count": 6,
    "issues_by_severity": {
        "critical": 0,
        "high": 2,
        "medium": 3,
        "low": 1,
        "info": 0
    },
    "issues": [],
    "summary": {},
    "vulnerabilities": [],
    "vulnerabilities_count": 0,
    "hardening": {}
}
```

### Input de `aipatch/audit-suspicious`

```json
{
    "input": {
        "scope": "uploads",
        "max_files": 25,
        "max_file_size": 262144,
        "with_hashes": true,
        "with_excerpt": false,
        "async": true
    }
}
```

### Input de `aipatch/get-async-job-status`

```json
{
    "input": {
        "job_id": "f0f34b26-7bb1-497f-b60d-52e4f7c31c09"
    }
}
```

### Output esperado de `aipatch/audit-suspicious` (resumen, modo sync)

```json
{
    "success": true,
    "generated_at_gmt": "2026-04-16T11:31:00+00:00",
    "scope": "uploads",
    "suspicious_count": 2,
    "scanned_files": 880,
    "inspected_files": 842,
    "skipped_large": 38,
    "max_files": 25,
    "truncated": false,
    "items": [
        {
            "path": "wp-content/uploads/2026/04/cache.php",
            "size": 3480,
            "modified_gmt": "2026-04-16T11:15:22+00:00",
            "risk_level": "high",
            "reasons": [
                "php_file_in_uploads",
                "obfuscated_eval_base64"
            ],
            "sha256": "..."
        }
    ]
}
```

### Output esperado de `aipatch/get-async-job-status` (resumen)

```json
{
    "success": true,
    "async": true,
    "job_id": "f0f34b26-7bb1-497f-b60d-52e4f7c31c09",
    "job_type": "audit-suspicious",
    "status": "completed",
    "created_at_gmt": "2026-04-16T11:30:00+00:00",
    "updated_at_gmt": "2026-04-16T11:30:04+00:00",
    "error": null,
    "has_result": true,
    "result": {}
}
```

### Recomendaciones para MCP externo

1. Ejecutar `aipatch/audit-site` en async (`async=true`) para no bloquear al agente.
2. Hacer polling con `aipatch/get-async-job-status` hasta `status=completed`.
3. Si hay riesgo medio/alto o indicadores de payload, lanzar `aipatch/audit-suspicious` (preferiblemente en async).
4. Priorizar analisis de `items` con `risk_level=high`.
5. Conservar y correlacionar hashes SHA-256 entre escaneos.

### Seguridad y permisos

- Estas abilities usan control de permisos por capacidad WordPress.
- Capacidad requerida por defecto: `manage_options`.
- Se puede personalizar por filtro:

```php
add_filter( 'aipatch_abilities_required_capability', function () {
        return 'manage_options';
} );
```

- Para agentes externos, usar usuario tecnico dedicado + Application Password + TLS.

