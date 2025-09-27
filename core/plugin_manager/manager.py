"""Enhanced plugin manager with security validation and health monitoring."""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from fastapi import HTTPException
import logging

from .models import PluginManifest, PluginInfo, PluginStatus, PluginHealth, HealthStatus
from .validator import SecurityValidator
from .health import HealthMonitor
from .registry import PluginRegistry
from core.identity.auth import AuthManager
from core.policy.engine import policy_engine
from core.audit.models import AuditCategory

logger = logging.getLogger(__name__)


class EnhancedPluginManager:
    """Enhanced plugin manager with comprehensive security and monitoring."""

    def __init__(
        self,
        jwt_secret: str,
        health_check_interval: int = 30,
        failure_threshold: int = 3,
    ):
        """
        Initialize enhanced plugin manager.

        Args:
            jwt_secret: Secret for JWT token generation
            health_check_interval: Health check interval in seconds
            failure_threshold: Failure threshold for health monitoring
        """
        self.registry = PluginRegistry(jwt_secret)
        self.validator = SecurityValidator()
        self.health_monitor = HealthMonitor(health_check_interval, failure_threshold)
        self.auth_manager = AuthManager(jwt_secret)

        self.plugins: Dict[str, PluginInfo] = {}
        self._shutdown = False

    async def register_plugin(
        self, manifest_data: Dict[str, Any], registration_token: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Register a plugin with comprehensive security validation.

        Args:
            manifest_data: Plugin manifest data
            registration_token: Optional registration token for authentication

        Returns:
            Registration response with token and status
        """
        try:
            # Validate and parse manifest
            try:
                manifest = PluginManifest(**manifest_data)
            except Exception as e:
                raise HTTPException(
                    status_code=400, detail=f"Invalid manifest format: {str(e)}"
                )

            # Validate registration token if provided
            if registration_token:
                if not self._validate_registration_token(registration_token):
                    raise HTTPException(
                        status_code=401, detail="Invalid registration token"
                    )

            # Comprehensive security validation
            is_secure, security_errors = self.validator.validate_manifest_security(
                manifest
            )
            if not is_secure:
                raise HTTPException(
                    status_code=400,
                    detail=f"Security validation failed: {'; '.join(security_errors)}",
                )

            # Check for duplicate registration
            if manifest.id in self.plugins:
                raise HTTPException(
                    status_code=409, detail=f"Plugin {manifest.id} already registered"
                )

            # Validate dependencies
            missing_deps = await self._check_dependencies(manifest.dependencies)
            if missing_deps:
                logger.warning(
                    f"Missing dependencies for {manifest.id}: {missing_deps}"
                )

            # Generate secure plugin token
            plugin_token = self.auth_manager.generate_plugin_token(
                manifest.id, manifest.traits
            )

            # Initialize plugin health
            initial_health = PluginHealth(
                status=HealthStatus.UNKNOWN,
                last_check=datetime.utcnow(),
                consecutive_failures=0,
            )

            # Create plugin info
            plugin_info = PluginInfo(
                manifest=manifest,
                status=PluginStatus.REGISTERED,
                health=initial_health,
                registered_at=datetime.utcnow(),
                token=plugin_token,
            )

            # Store plugin
            self.plugins[manifest.id] = plugin_info

            # Start health monitoring if configured
            if manifest.health_check:
                await self.health_monitor.start_monitoring(
                    manifest.id, manifest.health_check
                )

            # Audit registration
            await self._audit_plugin_registration(manifest.id, manifest.traits, True)

            logger.info(f"Plugin registered successfully: {manifest.id}")

            # Return registration response (exclude token from stored info)
            plugin_info.token = None

            return {
                "status": "registered",
                "plugin_id": manifest.id,
                "token": plugin_token,
                "health_monitoring": manifest.health_check is not None,
            }

        except HTTPException:
            # Re-raise HTTP exceptions as-is
            raise
        except Exception as e:
            # Log and convert other exceptions
            logger.error(f"Plugin registration failed: {e}")
            await self._audit_plugin_registration(
                manifest_data.get("id", "unknown"),
                manifest_data.get("traits", []),
                False,
                str(e),
            )
            raise HTTPException(
                status_code=500, detail=f"Registration failed: {str(e)}"
            )

    async def unregister_plugin(
        self, plugin_id: str, reason: Optional[str] = None
    ) -> bool:
        """
        Unregister a plugin and clean up resources.

        Args:
            plugin_id: Plugin ID to unregister
            reason: Reason for unregistration

        Returns:
            True if successful
        """
        try:
            if plugin_id not in self.plugins:
                raise HTTPException(
                    status_code=404, detail=f"Plugin {plugin_id} not found"
                )

            plugin_info = self.plugins[plugin_id]

            # Stop health monitoring
            await self.health_monitor.stop_monitoring(plugin_id)

            # Update status
            plugin_info.status = PluginStatus.INACTIVE
            plugin_info.disabled_reason = reason

            # Remove from registry
            del self.plugins[plugin_id]

            # Audit unregistration
            await self._audit_plugin_event(
                "plugin_unregistered", plugin_id, {"reason": reason}
            )

            logger.info(f"Plugin unregistered: {plugin_id}, reason: {reason}")
            return True

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to unregister plugin {plugin_id}: {e}")
            raise HTTPException(
                status_code=500, detail=f"Unregistration failed: {str(e)}"
            )

    async def disable_plugin(
        self, plugin_id: str, reason: str, disabled_by: Optional[str] = None
    ) -> bool:
        """
        Disable a plugin due to security or health issues.

        Args:
            plugin_id: Plugin ID to disable
            reason: Reason for disabling
            disabled_by: User who disabled the plugin

        Returns:
            True if successful
        """
        try:
            if plugin_id not in self.plugins:
                raise HTTPException(
                    status_code=404, detail=f"Plugin {plugin_id} not found"
                )

            plugin_info = self.plugins[plugin_id]

            # Update status
            plugin_info.status = PluginStatus.DISABLED
            plugin_info.disabled_reason = reason

            # Stop health monitoring
            await self.health_monitor.stop_monitoring(plugin_id)

            # Audit disabling
            await self._audit_plugin_event(
                "plugin_disabled",
                plugin_id,
                {
                    "reason": reason,
                    "disabled_by": disabled_by,
                    "previous_status": plugin_info.status.value,
                },
            )

            logger.warning(f"Plugin disabled: {plugin_id}, reason: {reason}")
            return True

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to disable plugin {plugin_id}: {e}")
            raise HTTPException(status_code=500, detail=f"Disable failed: {str(e)}")

    async def enable_plugin(
        self, plugin_id: str, enabled_by: Optional[str] = None
    ) -> bool:
        """
        Enable a previously disabled plugin.

        Args:
            plugin_id: Plugin ID to enable
            enabled_by: User who enabled the plugin

        Returns:
            True if successful
        """
        try:
            if plugin_id not in self.plugins:
                raise HTTPException(
                    status_code=404, detail=f"Plugin {plugin_id} not found"
                )

            plugin_info = self.plugins[plugin_id]

            if plugin_info.status != PluginStatus.DISABLED:
                raise HTTPException(
                    status_code=400, detail=f"Plugin {plugin_id} is not disabled"
                )

            # Re-validate security before enabling
            is_secure, security_errors = self.validator.validate_manifest_security(
                plugin_info.manifest
            )
            if not is_secure:
                raise HTTPException(
                    status_code=400,
                    detail=f"Security validation failed: {'; '.join(security_errors)}",
                )

            # Update status
            plugin_info.status = PluginStatus.ACTIVE
            plugin_info.disabled_reason = None

            # Restart health monitoring if configured
            if plugin_info.manifest.health_check:
                await self.health_monitor.start_monitoring(
                    plugin_id, plugin_info.manifest.health_check
                )

            # Audit enabling
            await self._audit_plugin_event(
                "plugin_enabled", plugin_id, {"enabled_by": enabled_by}
            )

            logger.info(f"Plugin enabled: {plugin_id}")
            return True

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to enable plugin {plugin_id}: {e}")
            raise HTTPException(status_code=500, detail=f"Enable failed: {str(e)}")

    async def heartbeat(self, plugin_id: str, status_data: Dict[str, Any]) -> bool:
        """
        Update plugin heartbeat and status.

        Args:
            plugin_id: Plugin ID
            status_data: Status information from plugin

        Returns:
            True if successful
        """
        try:
            if plugin_id not in self.plugins:
                return False

            plugin_info = self.plugins[plugin_id]

            # Update heartbeat
            plugin_info.last_heartbeat = datetime.utcnow()

            # Update status if provided
            if "status" in status_data:
                try:
                    new_status = PluginStatus(status_data["status"])
                    if new_status != plugin_info.status:
                        old_status = plugin_info.status
                        plugin_info.status = new_status

                        # Audit status change
                        await self._audit_plugin_event(
                            "plugin_status_change",
                            plugin_id,
                            {
                                "old_status": old_status.value,
                                "new_status": new_status.value,
                            },
                        )
                except ValueError:
                    logger.warning(
                        f"Invalid status from plugin {plugin_id}: {status_data['status']}"
                    )

            # Update health information
            if "health" in status_data:
                health_data = status_data["health"]
                plugin_info.health.metrics.update(health_data.get("metrics", {}))

                if "uptime" in health_data:
                    plugin_info.health.uptime_seconds = health_data["uptime"]
                if "memory_usage" in health_data:
                    plugin_info.health.memory_usage_mb = health_data["memory_usage"]
                if "cpu_usage" in health_data:
                    plugin_info.health.cpu_usage_percent = health_data["cpu_usage"]

            return True

        except Exception as e:
            logger.error(f"Heartbeat failed for plugin {plugin_id}: {e}")
            return False

    async def get_plugin_info(self, plugin_id: str) -> Optional[PluginInfo]:
        """Get information about a specific plugin."""
        plugin_info = self.plugins.get(plugin_id)
        if plugin_info:
            # Update with latest health status
            latest_health = await self.health_monitor.get_plugin_health(plugin_id)
            if latest_health:
                plugin_info.health = latest_health
        return plugin_info

    async def list_plugins(
        self,
        status: Optional[PluginStatus] = None,
        health_status: Optional[HealthStatus] = None,
    ) -> List[PluginInfo]:
        """
        List plugins with optional filtering.

        Args:
            status: Filter by plugin status
            health_status: Filter by health status

        Returns:
            List of plugin information
        """
        plugins = []

        for plugin_id, plugin_info in self.plugins.items():
            # Update with latest health status
            latest_health = await self.health_monitor.get_plugin_health(plugin_id)
            if latest_health:
                plugin_info.health = latest_health

            # Apply filters
            if status and plugin_info.status != status:
                continue
            if health_status and plugin_info.health.status != health_status:
                continue

            # Remove token from response
            safe_info = plugin_info.copy()
            safe_info.token = None
            plugins.append(safe_info)

        return plugins

    async def get_unhealthy_plugins(self) -> List[str]:
        """Get list of unhealthy plugin IDs."""
        return await self.health_monitor.get_unhealthy_plugins()

    async def validate_plugin_operation(
        self,
        plugin_id: str,
        operation: str,
        target: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, str]:
        """
        Validate a plugin operation using security policies.

        Args:
            plugin_id: Plugin performing the operation
            operation: Operation type
            target: Target resource
            data: Operation data

        Returns:
            Tuple of (is_allowed, reason)
        """
        try:
            # Check if plugin exists and is active
            if plugin_id not in self.plugins:
                return False, f"Plugin {plugin_id} not registered"

            plugin_info = self.plugins[plugin_id]

            if plugin_info.status not in [PluginStatus.ACTIVE, PluginStatus.REGISTERED]:
                return (
                    False,
                    f"Plugin {plugin_id} is not active (status: {plugin_info.status.value})",
                )

            # Check health status
            if plugin_info.health.status == HealthStatus.UNHEALTHY:
                return False, f"Plugin {plugin_id} is unhealthy"

            # Use security validator
            return self.validator.validate_plugin_operation(
                plugin_id, operation, target, data
            )

        except Exception as e:
            logger.error(f"Error validating plugin operation: {e}")
            return False, "Validation error occurred"

    async def shutdown(self):
        """Shutdown plugin manager and clean up resources."""
        self._shutdown = True

        # Stop health monitoring
        await self.health_monitor.shutdown()

        # Audit shutdown
        try:
            await self._audit_plugin_event(
                "plugin_manager_shutdown", "system", {"plugin_count": len(self.plugins)}
            )
        except Exception as e:
            logger.error(f"Failed to audit plugin manager shutdown: {e}")

        logger.info("Plugin manager shutdown complete")

    async def _check_dependencies(self, dependencies: List[str]) -> List[str]:
        """Check for missing plugin dependencies."""
        missing = []
        for dep in dependencies:
            if dep not in self.plugins:
                missing.append(dep)
            elif self.plugins[dep].status not in [
                PluginStatus.ACTIVE,
                PluginStatus.REGISTERED,
            ]:
                missing.append(f"{dep} (inactive)")
        return missing

    def _validate_registration_token(self, token: str) -> bool:
        """Validate plugin registration token."""
        # This could validate against a pre-shared secret or database
        # For now, just check if it's not empty
        return bool(token and len(token) >= 8)

    async def _audit_plugin_registration(
        self,
        plugin_id: str,
        traits: List[str],
        success: bool,
        error: Optional[str] = None,
    ):
        """Audit plugin registration events."""
        try:
            # Import here to avoid circular dependency
            from core.audit.service import get_audit_service

            audit_service = await get_audit_service()
            await audit_service.log_event(
                event_type="plugin_registration",
                category=AuditCategory.SYSTEM,
                action="register",
                result="success" if success else "failure",
                plugin_id=plugin_id,
                resource_type="plugin",
                resource_id=plugin_id,
                description=f'Plugin registration {"succeeded" if success else "failed"}',
                details={"traits": traits, "error": error if not success else None},
            )
        except Exception as e:
            logger.error(f"Failed to audit plugin registration: {e}")

    async def _audit_plugin_event(
        self, event_type: str, plugin_id: str, details: Dict[str, Any]
    ):
        """Audit plugin-related events."""
        try:
            from core.audit.service import get_audit_service

            audit_service = await get_audit_service()
            await audit_service.log_event(
                event_type=event_type,
                category=AuditCategory.SYSTEM,
                action="manage",
                result="success",
                plugin_id=plugin_id,
                resource_type="plugin",
                resource_id=plugin_id,
                description=f"Plugin event: {event_type}",
                details=details,
            )
        except Exception as e:
            logger.error(f"Failed to audit plugin event {event_type}: {e}")
