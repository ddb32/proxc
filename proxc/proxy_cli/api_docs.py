"""OpenAPI Documentation Generator - Phase 4.2.7 Implementation

This module generates OpenAPI/Swagger documentation for the REST API,
providing interactive documentation for API consumers.
"""

import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path

from .cli_base import get_cli_logger
from .api_auth import APIPermissions


class OpenAPIGenerator:
    """Generates OpenAPI 3.0 specification for the REST API"""
    
    def __init__(self, version: str = "1.0.0", title: str = "ProxC API"):
        self.logger = get_cli_logger("api_docs")
        self.version = version
        self.title = title
        
        # Base OpenAPI structure
        self.spec = {
            "openapi": "3.0.0",
            "info": {
                "title": title,
                "version": version,
                "description": "REST API for ProxC - comprehensive proxy discovery and validation system",
                "contact": {
                    "name": "ProxC API Support",
                    "url": "https://github.com/proxc/proxc"
                },
                "license": {
                    "name": "MIT",
                    "url": "https://opensource.org/licenses/MIT"
                }
            },
            "servers": [
                {
                    "url": "http://localhost:8080/api/v1",
                    "description": "Local development server"
                }
            ],
            "components": {
                "securitySchemes": {
                    "ApiKeyAuth": {
                        "type": "apiKey",
                        "in": "header",
                        "name": "X-API-Key",
                        "description": "API key for authentication"
                    },
                    "BearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                        "description": "Bearer token authentication"
                    }
                },
                "schemas": {},
                "responses": {},
                "parameters": {}
            },
            "security": [
                {"ApiKeyAuth": []},
                {"BearerAuth": []}
            ],
            "paths": {}
        }
        
        self._define_schemas()
        self._define_responses()
        self._define_parameters()
        self._define_paths()
    
    def _define_schemas(self):
        """Define reusable schemas"""
        self.spec["components"]["schemas"] = {
            "Proxy": {
                "type": "object",
                "properties": {
                    "proxy_id": {"type": "string", "description": "Unique identifier for the proxy"},
                    "address": {"type": "string", "description": "Full proxy address (host:port)"},
                    "host": {"type": "string", "description": "Proxy hostname or IP address"},
                    "port": {"type": "integer", "description": "Proxy port number"},
                    "protocol": {
                        "type": "string",
                        "enum": ["http", "https", "socks4", "socks5"],
                        "description": "Proxy protocol type"
                    },
                    "status": {
                        "type": "string",
                        "enum": ["active", "inactive", "failed"],
                        "description": "Proxy validation status"
                    },
                    "anonymity_level": {
                        "type": "string",
                        "enum": ["transparent", "anonymous", "elite"],
                        "description": "Level of anonymity provided"
                    },
                    "threat_level": {
                        "type": "string",
                        "enum": ["low", "medium", "high", "critical"],
                        "description": "Security threat assessment"
                    },
                    "country": {"type": "string", "description": "Country name"},
                    "country_code": {"type": "string", "description": "ISO country code"},
                    "city": {"type": "string", "description": "City location"},
                    "response_time": {"type": "number", "description": "Response time in milliseconds"},
                    "success_rate": {"type": "number", "description": "Success rate percentage"},
                    "last_checked": {"type": "string", "format": "date-time", "description": "Last validation timestamp"}
                },
                "required": ["proxy_id", "address", "host", "port", "protocol", "status"]
            },
            "ProxyList": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "data": {
                        "type": "object",
                        "properties": {
                            "proxies": {
                                "type": "array",
                                "items": {"$ref": "#/components/schemas/Proxy"}
                            },
                            "total_count": {"type": "integer"},
                            "has_more": {"type": "boolean"}
                        }
                    },
                    "pagination": {
                        "type": "object",
                        "properties": {
                            "limit": {"type": "integer"},
                            "offset": {"type": "integer"},
                            "total": {"type": "integer"},
                            "has_more": {"type": "boolean"}
                        }
                    },
                    "timestamp": {"type": "string", "format": "date-time"}
                },
                "required": ["success", "data", "timestamp"]
            },
            "Statistics": {
                "type": "object",
                "properties": {
                    "total_proxies": {"type": "integer", "description": "Total number of proxies"},
                    "active_proxies": {"type": "integer", "description": "Number of active proxies"},
                    "failed_proxies": {"type": "integer", "description": "Number of failed proxies"},
                    "success_rate": {"type": "number", "description": "Overall success rate percentage"},
                    "avg_response_time": {"type": "number", "description": "Average response time in milliseconds"},
                    "country_distribution": {
                        "type": "object",
                        "additionalProperties": {"type": "integer"},
                        "description": "Proxy count by country"
                    },
                    "protocol_distribution": {
                        "type": "object",
                        "additionalProperties": {"type": "integer"},
                        "description": "Proxy count by protocol"
                    }
                }
            },
            "Profile": {
                "type": "object",
                "properties": {
                    "profile": {"type": "string", "description": "Profile name"},
                    "description": {"type": "string", "description": "Profile description"},
                    "category": {"type": "string", "description": "Profile category"},
                    "tags": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Profile tags"
                    },
                    "commands": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Commands to execute"
                    },
                    "defaults": {
                        "type": "object",
                        "additionalProperties": true,
                        "description": "Default parameter values"
                    }
                },
                "required": ["profile", "description", "commands"]
            },
            "APIKey": {
                "type": "object",
                "properties": {
                    "key_id": {"type": "string", "description": "Unique key identifier"},
                    "name": {"type": "string", "description": "Human-readable key name"},
                    "permissions": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of permissions granted to this key"
                    },
                    "rate_limit": {"type": "integer", "description": "Requests per minute limit"},
                    "created_at": {"type": "string", "format": "date-time"},
                    "last_used": {"type": "string", "format": "date-time"},
                    "is_active": {"type": "boolean", "description": "Whether the key is active"},
                    "expires_at": {"type": "string", "format": "date-time"}
                },
                "required": ["key_id", "name", "permissions", "rate_limit", "created_at", "is_active"]
            },
            "Error": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean", "example": False},
                    "error": {"type": "string", "description": "Error type"},
                    "message": {"type": "string", "description": "Human-readable error message"},
                    "timestamp": {"type": "string", "format": "date-time"}
                },
                "required": ["success", "error", "message", "timestamp"]
            },
            "CreateProxyRequest": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "Proxy hostname or IP address"},
                    "port": {"type": "integer", "description": "Proxy port number"},
                    "protocol": {
                        "type": "string",
                        "enum": ["http", "https", "socks4", "socks5"],
                        "description": "Proxy protocol type"
                    },
                    "username": {"type": "string", "description": "Optional username for authentication"},
                    "password": {"type": "string", "description": "Optional password for authentication"},
                    "source": {"type": "string", "description": "Source of the proxy"}
                },
                "required": ["host", "port", "protocol"]
            },
            "CreateAPIKeyRequest": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Human-readable key name"},
                    "permissions": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of permissions to grant",
                        "default": ["read:proxies", "read:stats"]
                    },
                    "rate_limit": {"type": "integer", "description": "Requests per minute limit", "default": 100},
                    "expires_in_days": {"type": "integer", "description": "Optional expiration in days"}
                },
                "required": ["name"]
            }
        }
    
    def _define_responses(self):
        """Define reusable responses"""
        self.spec["components"]["responses"] = {
            "BadRequest": {
                "description": "Bad request",
                "content": {
                    "application/json": {
                        "schema": {"$ref": "#/components/schemas/Error"}
                    }
                }
            },
            "Unauthorized": {
                "description": "Authentication required",
                "content": {
                    "application/json": {
                        "schema": {"$ref": "#/components/schemas/Error"}
                    }
                }
            },
            "Forbidden": {
                "description": "Insufficient permissions",
                "content": {
                    "application/json": {
                        "schema": {"$ref": "#/components/schemas/Error"}
                    }
                }
            },
            "NotFound": {
                "description": "Resource not found",
                "content": {
                    "application/json": {
                        "schema": {"$ref": "#/components/schemas/Error"}
                    }
                }
            },
            "RateLimited": {
                "description": "Rate limit exceeded",
                "headers": {
                    "X-RateLimit-Limit": {
                        "schema": {"type": "integer"},
                        "description": "Request limit per minute"
                    },
                    "X-RateLimit-Remaining": {
                        "schema": {"type": "integer"},
                        "description": "Remaining requests in current window"
                    },
                    "Retry-After": {
                        "schema": {"type": "integer"},
                        "description": "Seconds until rate limit resets"
                    }
                },
                "content": {
                    "application/json": {
                        "schema": {"$ref": "#/components/schemas/Error"}
                    }
                }
            },
            "InternalError": {
                "description": "Internal server error",
                "content": {
                    "application/json": {
                        "schema": {"$ref": "#/components/schemas/Error"}
                    }
                }
            }
        }
    
    def _define_parameters(self):
        """Define reusable parameters"""
        self.spec["components"]["parameters"] = {
            "LimitParam": {
                "name": "limit",
                "in": "query",
                "description": "Number of items to return",
                "schema": {
                    "type": "integer",
                    "default": 100,
                    "minimum": 1,
                    "maximum": 1000
                }
            },
            "OffsetParam": {
                "name": "offset",
                "in": "query",
                "description": "Number of items to skip",
                "schema": {
                    "type": "integer",
                    "default": 0,
                    "minimum": 0
                }
            },
            "StatusFilter": {
                "name": "status",
                "in": "query",
                "description": "Filter by proxy status",
                "schema": {
                    "type": "string",
                    "enum": ["active", "inactive", "failed"]
                }
            },
            "ProtocolFilter": {
                "name": "protocol",
                "in": "query",
                "description": "Filter by proxy protocol",
                "schema": {
                    "type": "string",
                    "enum": ["http", "https", "socks4", "socks5"]
                }
            },
            "CountryFilter": {
                "name": "country",
                "in": "query",
                "description": "Filter by country code",
                "schema": {
                    "type": "string",
                    "pattern": "^[A-Z]{2}$"
                }
            }
        }
    
    def _define_paths(self):
        """Define all API paths"""
        self.spec["paths"] = {
            "/proxies": {
                "get": {
                    "summary": "List proxies",
                    "description": "Retrieve a paginated list of proxies with optional filtering",
                    "tags": ["Proxies"],
                    "security": [{"ApiKeyAuth": []}, {"BearerAuth": []}],
                    "parameters": [
                        {"$ref": "#/components/parameters/LimitParam"},
                        {"$ref": "#/components/parameters/OffsetParam"},
                        {"$ref": "#/components/parameters/StatusFilter"},
                        {"$ref": "#/components/parameters/ProtocolFilter"},
                        {"$ref": "#/components/parameters/CountryFilter"}
                    ],
                    "responses": {
                        "200": {
                            "description": "Successful response",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/ProxyList"}
                                }
                            }
                        },
                        "400": {"$ref": "#/components/responses/BadRequest"},
                        "401": {"$ref": "#/components/responses/Unauthorized"},
                        "403": {"$ref": "#/components/responses/Forbidden"},
                        "429": {"$ref": "#/components/responses/RateLimited"},
                        "500": {"$ref": "#/components/responses/InternalError"}
                    }
                },
                "post": {
                    "summary": "Create proxy",
                    "description": "Add a new proxy to the collection",
                    "tags": ["Proxies"],
                    "security": [{"ApiKeyAuth": []}, {"BearerAuth": []}],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/CreateProxyRequest"}
                            }
                        }
                    },
                    "responses": {
                        "201": {
                            "description": "Proxy created successfully",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "allOf": [
                                            {
                                                "type": "object",
                                                "properties": {
                                                    "success": {"type": "boolean"},
                                                    "message": {"type": "string"},
                                                    "timestamp": {"type": "string", "format": "date-time"}
                                                }
                                            },
                                            {
                                                "type": "object",
                                                "properties": {
                                                    "data": {"$ref": "#/components/schemas/Proxy"}
                                                }
                                            }
                                        ]
                                    }
                                }
                            }
                        },
                        "400": {"$ref": "#/components/responses/BadRequest"},
                        "401": {"$ref": "#/components/responses/Unauthorized"},
                        "403": {"$ref": "#/components/responses/Forbidden"},
                        "429": {"$ref": "#/components/responses/RateLimited"},
                        "500": {"$ref": "#/components/responses/InternalError"}
                    }
                }
            },
            "/proxies/{proxyId}": {
                "parameters": [
                    {
                        "name": "proxyId",
                        "in": "path",
                        "required": True,
                        "description": "Unique proxy identifier",
                        "schema": {"type": "string"}
                    }
                ],
                "get": {
                    "summary": "Get proxy details",
                    "description": "Retrieve detailed information about a specific proxy",
                    "tags": ["Proxies"],
                    "security": [{"ApiKeyAuth": []}, {"BearerAuth": []}],
                    "responses": {
                        "200": {
                            "description": "Proxy details",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "success": {"type": "boolean"},
                                            "data": {"$ref": "#/components/schemas/Proxy"},
                                            "timestamp": {"type": "string", "format": "date-time"}
                                        }
                                    }
                                }
                            }
                        },
                        "401": {"$ref": "#/components/responses/Unauthorized"},
                        "403": {"$ref": "#/components/responses/Forbidden"},
                        "404": {"$ref": "#/components/responses/NotFound"},
                        "429": {"$ref": "#/components/responses/RateLimited"},
                        "500": {"$ref": "#/components/responses/InternalError"}
                    }
                },
                "delete": {
                    "summary": "Delete proxy",
                    "description": "Remove a proxy from the collection",
                    "tags": ["Proxies"],
                    "security": [{"ApiKeyAuth": []}, {"BearerAuth": []}],
                    "responses": {
                        "200": {
                            "description": "Proxy deleted successfully",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "success": {"type": "boolean"},
                                            "message": {"type": "string"},
                                            "timestamp": {"type": "string", "format": "date-time"}
                                        }
                                    }
                                }
                            }
                        },
                        "401": {"$ref": "#/components/responses/Unauthorized"},
                        "403": {"$ref": "#/components/responses/Forbidden"},
                        "404": {"$ref": "#/components/responses/NotFound"},
                        "429": {"$ref": "#/components/responses/RateLimited"},
                        "500": {"$ref": "#/components/responses/InternalError"}
                    }
                }
            },
            "/stats": {
                "get": {
                    "summary": "Get statistics",
                    "description": "Retrieve comprehensive proxy statistics and analytics",
                    "tags": ["Statistics"],
                    "security": [{"ApiKeyAuth": []}, {"BearerAuth": []}],
                    "responses": {
                        "200": {
                            "description": "Statistics data",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "success": {"type": "boolean"},
                                            "data": {"$ref": "#/components/schemas/Statistics"},
                                            "timestamp": {"type": "string", "format": "date-time"}
                                        }
                                    }
                                }
                            }
                        },
                        "401": {"$ref": "#/components/responses/Unauthorized"},
                        "403": {"$ref": "#/components/responses/Forbidden"},
                        "429": {"$ref": "#/components/responses/RateLimited"},
                        "500": {"$ref": "#/components/responses/InternalError"}
                    }
                }
            },
            "/profiles": {
                "get": {
                    "summary": "List profiles",
                    "description": "Retrieve available configuration profiles",
                    "tags": ["Profiles"],
                    "security": [{"ApiKeyAuth": []}, {"BearerAuth": []}],
                    "responses": {
                        "200": {
                            "description": "List of profiles",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "success": {"type": "boolean"},
                                            "data": {
                                                "type": "object",
                                                "properties": {
                                                    "profiles": {
                                                        "type": "object",
                                                        "additionalProperties": {
                                                            "type": "object",
                                                            "additionalProperties": {"$ref": "#/components/schemas/Profile"}
                                                        }
                                                    },
                                                    "total_count": {"type": "integer"}
                                                }
                                            },
                                            "timestamp": {"type": "string", "format": "date-time"}
                                        }
                                    }
                                }
                            }
                        },
                        "401": {"$ref": "#/components/responses/Unauthorized"},
                        "403": {"$ref": "#/components/responses/Forbidden"},
                        "429": {"$ref": "#/components/responses/RateLimited"},
                        "500": {"$ref": "#/components/responses/InternalError"}
                    }
                }
            },
            "/auth/keys": {
                "get": {
                    "summary": "List API keys",
                    "description": "Retrieve list of API keys (admin only)",
                    "tags": ["Authentication"],
                    "security": [{"ApiKeyAuth": []}, {"BearerAuth": []}],
                    "responses": {
                        "200": {
                            "description": "List of API keys",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "success": {"type": "boolean"},
                                            "data": {
                                                "type": "object",
                                                "properties": {
                                                    "keys": {
                                                        "type": "array",
                                                        "items": {"$ref": "#/components/schemas/APIKey"}
                                                    },
                                                    "total_count": {"type": "integer"}
                                                }
                                            },
                                            "timestamp": {"type": "string", "format": "date-time"}
                                        }
                                    }
                                }
                            }
                        },
                        "401": {"$ref": "#/components/responses/Unauthorized"},
                        "403": {"$ref": "#/components/responses/Forbidden"},
                        "429": {"$ref": "#/components/responses/RateLimited"},
                        "500": {"$ref": "#/components/responses/InternalError"}
                    }
                },
                "post": {
                    "summary": "Create API key",
                    "description": "Generate a new API key (admin only)",
                    "tags": ["Authentication"],
                    "security": [{"ApiKeyAuth": []}, {"BearerAuth": []}],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/CreateAPIKeyRequest"}
                            }
                        }
                    },
                    "responses": {
                        "201": {
                            "description": "API key created successfully",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "success": {"type": "boolean"},
                                            "data": {
                                                "type": "object",
                                                "properties": {
                                                    "key_id": {"type": "string"},
                                                    "api_key": {"type": "string", "description": "Full API key (shown only once)"},
                                                    "name": {"type": "string"},
                                                    "permissions": {"type": "array", "items": {"type": "string"}},
                                                    "rate_limit": {"type": "integer"}
                                                }
                                            },
                                            "message": {"type": "string"},
                                            "timestamp": {"type": "string", "format": "date-time"}
                                        }
                                    }
                                }
                            }
                        },
                        "400": {"$ref": "#/components/responses/BadRequest"},
                        "401": {"$ref": "#/components/responses/Unauthorized"},
                        "403": {"$ref": "#/components/responses/Forbidden"},
                        "429": {"$ref": "#/components/responses/RateLimited"},
                        "500": {"$ref": "#/components/responses/InternalError"}
                    }
                }
            }
        }
    
    def generate_spec(self) -> Dict[str, Any]:
        """Generate the complete OpenAPI specification"""
        return self.spec
    
    def save_spec(self, output_path: Path) -> None:
        """Save the OpenAPI specification to a file"""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(self.spec, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"OpenAPI specification saved to {output_path}")
            
        except Exception as e:
            self.logger.error(f"Error saving OpenAPI specification: {e}")
            raise
    
    def generate_html_docs(self, api_spec_url: str = "/api/v1/docs/spec") -> str:
        """Generate HTML documentation page using Swagger UI"""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self.title} - API Documentation</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui.css" />
    <style>
        html {{
            box-sizing: border-box;
            overflow: -moz-scrollbars-vertical;
            overflow-y: scroll;
        }}
        
        *, *:before, *:after {{
            box-sizing: inherit;
        }}
        
        body {{
            margin:0;
            background: #fafafa;
        }}
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {{
            const ui = SwaggerUIBundle({{
                url: '{api_spec_url}',
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout",
                validatorUrl: null,
                tryItOutEnabled: true,
                supportedSubmitMethods: ['get', 'post', 'put', 'delete', 'patch'],
                onComplete: function() {{
                    console.log('Swagger UI loaded successfully');
                }},
                onFailure: function(error) {{
                    console.error('Error loading API spec:', error);
                }}
            }});
            
            window.ui = ui;
        }};
    </script>
</body>
</html>"""


def create_api_docs():
    """Create API documentation files"""
    generator = OpenAPIGenerator()
    
    # Create docs directory
    docs_dir = Path(__file__).parent / "api_docs"
    docs_dir.mkdir(exist_ok=True)
    
    # Generate and save OpenAPI spec
    spec_path = docs_dir / "openapi.json"
    generator.save_spec(spec_path)
    
    # Generate HTML documentation
    html_docs = generator.generate_html_docs()
    html_path = docs_dir / "index.html"
    
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html_docs)
    
    return generator.generate_spec(), html_docs


if __name__ == '__main__':
    # Generate documentation
    spec, html = create_api_docs()
    print("API documentation generated successfully!")
    print(f"OpenAPI spec: {Path(__file__).parent / 'api_docs' / 'openapi.json'}")
    print(f"HTML docs: {Path(__file__).parent / 'api_docs' / 'index.html'}")