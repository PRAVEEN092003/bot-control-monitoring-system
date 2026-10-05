/**
 * static/js/dashboard.js
 * BotGuard CM — Phase 2 dashboard utilities.
 * Chart.js charts will be added in Phase 7 (admin dashboard).
 */

'use strict';

// Auto-dismiss flash alerts after 6 seconds
document.addEventListener('DOMContentLoaded', () => {
  const alerts = document.querySelectorAll('.bcms-alert');
  alerts.forEach(alert => {
    setTimeout(() => {
      const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
      if (bsAlert) bsAlert.close();
    }, 6000);
  });
});
