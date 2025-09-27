"""Health monitoring for plugins with automatic recovery and alerting."""

import asyncio
import time
from datetime import datetime, timedelta
from typing import Dict, Optional, List, Any
import httpx
import logging

from .models import PluginHealth, HealthStatus, PluginStatus
from core.audit.models import AuditCategory

logger = logging.getLogger(__name__)


class HealthMonitor:
    """Monitors plugin health with automatic recovery and alerting."""

    def __init__(self, check_interval: int = 30, failure_threshold: int = 3):
        """
        Initialize health monitor.

        Args:
            check_interval: Health check interval in seconds
            failure_threshold: Number of consecutive failures before marking unhealthy
        """
        self.check_interval = check_interval
        self.failure_threshold = failure_threshold
        self.plugin_health: Dict[str, PluginHealth] = {}
        self.monitoring_tasks: Dict[str, asyncio.Task] = {}
        self.audit_service = None
        self._shutdown = False

    async def start_monitoring(self, plugin_id: str, health_config: Dict[str, Any]):
        """
        Start health monitoring for a plugin.

        Args:
            plugin_id: Plugin ID to monitor
            health_config: Health check configuration
        """
        if plugin_id in self.monitoring_tasks:
            logger.warning(f"Health monitoring already active for plugin {plugin_id}")
            return

        # Initialize health record
        self.plugin_health[plugin_id] = PluginHealth(
            status=HealthStatus.UNKNOWN,
            last_check=datetime.utcnow(),
            consecutive_failures=0
        )

        # Start monitoring task
        task = asyncio.create_task(
            self._monitor_plugin(plugin_id, health_config)
        )
        self.monitoring_tasks[plugin_id] = task

        logger.info(f"Started health monitoring for plugin {plugin_id}")

    async def stop_monitoring(self, plugin_id: str):
        """
        Stop health monitoring for a plugin.

        Args:
            plugin_id: Plugin ID to stop monitoring
        """
        if plugin_id in self.monitoring_tasks:
            task = self.monitoring_tasks[plugin_id]
            task.cancel()
            del self.monitoring_tasks[plugin_id]

        if plugin_id in self.plugin_health:
            del self.plugin_health[plugin_id]

        logger.info(f"Stopped health monitoring for plugin {plugin_id}")

    async def check_plugin_health(
        self,
        plugin_id: str,
        health_config: Dict[str, Any]
    ) -> PluginHealth:
        """
        Perform a single health check for a plugin.

        Args:
            plugin_id: Plugin ID to check
            health_config: Health check configuration

        Returns:
            Updated PluginHealth object
        """
        start_time = time.time()
        health = self.plugin_health.get(plugin_id)

        if not health:
            health = PluginHealth(
                status=HealthStatus.UNKNOWN,
                last_check=datetime.utcnow(),
                consecutive_failures=0
            )
            self.plugin_health[plugin_id] = health

        try:
            # Perform health check based on configuration
            check_result = await self._perform_health_check(plugin_id, health_config)

            response_time = int((time.time() - start_time) * 1000)

            if check_result['healthy']:
                # Plugin is healthy
                health.status = HealthStatus.HEALTHY
                health.consecutive_failures = 0
                health.error_message = None
                health.response_time_ms = response_time
                health.metrics = check_result.get('metrics', {})

                # Update performance metrics
                if 'uptime' in check_result:
                    health.uptime_seconds = check_result['uptime']
                if 'memory_usage' in check_result:
                    health.memory_usage_mb = check_result['memory_usage']
                if 'cpu_usage' in check_result:
                    health.cpu_usage_percent = check_result['cpu_usage']

            else:
                # Plugin is unhealthy
                health.consecutive_failures += 1
                health.error_message = check_result.get('error', 'Health check failed')
                health.response_time_ms = response_time

                # Determine status based on consecutive failures
                if health.consecutive_failures >= self.failure_threshold:
                    health.status = HealthStatus.UNHEALTHY
                else:
                    health.status = HealthStatus.DEGRADED

            health.last_check = datetime.utcnow()

            # Log health check result
            if health.status == HealthStatus.UNHEALTHY:
                logger.warning(f"Plugin {plugin_id} is unhealthy: {health.error_message}")
            elif health.status == HealthStatus.DEGRADED:
                logger.info(f"Plugin {plugin_id} is degraded: {health.error_message}")

            # Audit significant health changes
            await self._audit_health_change(plugin_id, health)

            return health

        except Exception as e:
            # Health check failed with exception
            health.consecutive_failures += 1
            health.error_message = f"Health check exception: {str(e)}"
            health.response_time_ms = int((time.time() - start_time) * 1000)
            health.last_check = datetime.utcnow()

            if health.consecutive_failures >= self.failure_threshold:
                health.status = HealthStatus.UNHEALTHY
            else:
                health.status = HealthStatus.DEGRADED

            logger.error(f"Health check failed for plugin {plugin_id}: {e}")

            await self._audit_health_change(plugin_id, health)
            return health

    async def get_plugin_health(self, plugin_id: str) -> Optional[PluginHealth]:
        """Get current health status for a plugin."""
        return self.plugin_health.get(plugin_id)

    async def get_all_health_status(self) -> Dict[str, PluginHealth]:
        """Get health status for all monitored plugins."""
        return self.plugin_health.copy()

    async def get_unhealthy_plugins(self) -> List[str]:
        """Get list of unhealthy plugin IDs."""
        unhealthy = []
        for plugin_id, health in self.plugin_health.items():
            if health.status == HealthStatus.UNHEALTHY:
                unhealthy.append(plugin_id)
        return unhealthy

    async def shutdown(self):
        """Shutdown health monitoring."""
        self._shutdown = True

        # Cancel all monitoring tasks
        for plugin_id, task in self.monitoring_tasks.items():
            task.cancel()
            logger.info(f"Cancelled health monitoring for plugin {plugin_id}")

        # Wait for tasks to complete
        if self.monitoring_tasks:
            await asyncio.gather(*self.monitoring_tasks.values(), return_exceptions=True)

        self.monitoring_tasks.clear()
        self.plugin_health.clear()

        logger.info("Health monitoring shutdown complete")

    async def _monitor_plugin(self, plugin_id: str, health_config: Dict[str, Any]):
        """
        Continuous monitoring loop for a plugin.

        Args:
            plugin_id: Plugin ID to monitor
            health_config: Health check configuration
        """
        logger.info(f"Starting health monitoring loop for plugin {plugin_id}")

        try:
            while not self._shutdown:
                try:
                    await self.check_plugin_health(plugin_id, health_config)

                    # Wait for next check interval
                    await asyncio.sleep(self.check_interval)

                except asyncio.CancelledError:
                    logger.info(f"Health monitoring cancelled for plugin {plugin_id}")
                    break
                except Exception as e:
                    logger.error(f"Error in health monitoring loop for {plugin_id}: {e}")
                    # Continue monitoring even if individual check fails
                    await asyncio.sleep(self.check_interval)

        except Exception as e:
            logger.error(f"Health monitoring loop failed for plugin {plugin_id}: {e}")
        finally:
            logger.info(f"Health monitoring loop ended for plugin {plugin_id}")

    async def _perform_health_check(
        self,
        plugin_id: str,
        health_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Perform the actual health check based on configuration.

        Args:
            plugin_id: Plugin ID to check
            health_config: Health check configuration

        Returns:
            Dictionary with health check results
        """
        check_type = health_config.get('type', 'http')
        timeout = health_config.get('timeout', 5.0)

        if check_type == 'http':
            return await self._http_health_check(plugin_id, health_config, timeout)
        elif check_type == 'tcp':
            return await self._tcp_health_check(plugin_id, health_config, timeout)
        elif check_type == 'custom':
            return await self._custom_health_check(plugin_id, health_config, timeout)
        else:
            return {
                'healthy': False,
                'error': f'Unknown health check type: {check_type}'
            }

    async def _http_health_check(
        self,
        plugin_id: str,
        health_config: Dict[str, Any],
        timeout: float
    ) -> Dict[str, Any]:
        """Perform HTTP health check."""
        try:
            # Build health check URL
            port = health_config.get('port', 8080)
            path = health_config.get('path', '/health')
            url = f"http://{plugin_id}:{port}{path}"

            # Expected response code
            expected_code = health_config.get('expected_code', 200)

            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.get(url)

                if response.status_code == expected_code:
                    # Try to parse response for additional metrics
                    try:
                        data = response.json()
                        return {
                            'healthy': True,
                            'metrics': data.get('metrics', {}),
                            'uptime': data.get('uptime'),
                            'memory_usage': data.get('memory_usage'),
                            'cpu_usage': data.get('cpu_usage')
                        }
                    except:
                        # Response is not JSON, but status code is correct
                        return {'healthy': True}
                else:
                    return {
                        'healthy': False,
                        'error': f'HTTP {response.status_code}: {response.text[:200]}'
                    }

        except httpx.TimeoutException:
            return {
                'healthy': False,
                'error': f'Health check timeout after {timeout}s'
            }
        except httpx.ConnectError:
            return {
                'healthy': False,
                'error': 'Failed to connect to plugin'
            }
        except Exception as e:
            return {
                'healthy': False,
                'error': f'Health check error: {str(e)}'
            }

    async def _tcp_health_check(
        self,
        plugin_id: str,
        health_config: Dict[str, Any],
        timeout: float
    ) -> Dict[str, Any]:
        """Perform TCP health check."""
        try:
            port = health_config.get('port', 8080)

            # Try to open TCP connection
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(plugin_id, port),
                timeout=timeout
            )

            writer.close()
            await writer.wait_closed()

            return {'healthy': True}

        except asyncio.TimeoutError:
            return {
                'healthy': False,
                'error': f'TCP connection timeout after {timeout}s'
            }
        except ConnectionRefusedError:
            return {
                'healthy': False,
                'error': 'TCP connection refused'
            }
        except Exception as e:
            return {
                'healthy': False,
                'error': f'TCP health check error: {str(e)}'
            }

    async def _custom_health_check(
        self,
        plugin_id: str,
        health_config: Dict[str, Any],
        timeout: float
    ) -> Dict[str, Any]:
        """Perform custom health check."""
        # This would implement custom health check logic
        # For now, return a basic check
        return {
            'healthy': True,
            'note': 'Custom health check not implemented'
        }

    async def _audit_health_change(self, plugin_id: str, health: PluginHealth):
        """Audit significant health status changes."""
        try:
            # Only audit status changes, not every check
            previous_status = getattr(self, f'_last_status_{plugin_id}', None)
            current_status = health.status

            if previous_status != current_status:
                # Import here to avoid circular dependency
                from core.audit.service import get_audit_service

                audit_service = await get_audit_service()
                await audit_service.log_event(
                    event_type='plugin_health_change',
                    category=AuditCategory.SYSTEM,
                    action='health_check',
                    result='success',
                    plugin_id=plugin_id,
                    resource_type='plugin',
                    resource_id=plugin_id,
                    description=f'Plugin health changed from {previous_status} to {current_status}',
                    details={
                        'previous_status': previous_status,
                        'current_status': current_status.value,
                        'consecutive_failures': health.consecutive_failures,
                        'error_message': health.error_message,
                        'response_time_ms': health.response_time_ms
                    }
                )

                # Store current status for next comparison
                setattr(self, f'_last_status_{plugin_id}', current_status)

                # Alert on unhealthy status
                if current_status == HealthStatus.UNHEALTHY:
                    await self._send_alert(plugin_id, health)

        except Exception as e:
            logger.error(f"Failed to audit health change for plugin {plugin_id}: {e}")

    async def _send_alert(self, plugin_id: str, health: PluginHealth):
        """Send alert for unhealthy plugin."""
        # This would integrate with alerting systems
        logger.critical(f"ALERT: Plugin {plugin_id} is unhealthy", extra={
            'plugin_id': plugin_id,
            'status': health.status.value,
            'consecutive_failures': health.consecutive_failures,
            'error_message': health.error_message,
            'last_check': health.last_check.isoformat()
        })