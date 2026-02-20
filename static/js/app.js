(function () {
  function getCSRFToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
  }

  function initCSRF() {
    var token = getCSRFToken();
    if (!token || !window.htmx || !document.body) {
      return;
    }
    document.body.addEventListener('htmx:configRequest', function (evt) {
      evt.detail.headers['X-CSRF-Token'] = token;
    });
  }

  function initDeviceStatusBanner() {
    var banner = document.getElementById('conn-banner');
    if (!banner) {
      return;
    }
    var down = false;
    function check() {
      fetch('/device-status').then(function (r) {
        if (!r.ok) {
          throw r;
        }
        if (down) {
          down = false;
          banner.hidden = true;
        }
      }).catch(function () {
        if (!down) {
          down = true;
          banner.hidden = false;
        }
      });
    }
    setInterval(check, 10000);
  }

  function initProgressBars(root) {
    var scope = root || document;
    var bars = scope.querySelectorAll('.progress-bar[data-progress]');
    bars.forEach(function (bar) {
      var val = parseInt(bar.getAttribute('data-progress'), 10);
      if (!isNaN(val) && val >= 0) {
        bar.style.width = Math.min(val, 100) + '%';
      }
    });
  }

  function startRebootOverlay(root) {
    var scope = root || document;
    var overlay = scope.querySelector('.reboot-overlay');
    if (!overlay || overlay.dataset.init === 'true') {
      return;
    }
    overlay.dataset.init = 'true';

    var timeout = parseInt(overlay.getAttribute('data-timeout'), 10);
    if (isNaN(timeout) || timeout <= 0) {
      timeout = 120000;
    }
    var interval = parseInt(overlay.getAttribute('data-interval'), 10);
    if (isNaN(interval) || interval <= 0) {
      interval = 2000;
    }
    var start = Date.now();
    var status = overlay.querySelector('#reboot-status');
    var returnTo = window.location.pathname + window.location.search;

    function waitDown() {
      if (Date.now() - start > timeout) {
        if (status) {
          status.textContent = 'Timeout - device did not shut down within 2 minutes.';
          status.classList.add('is-error');
        }
        return;
      }
      fetch('/device-status').then(function (r) {
        if (r.ok) {
          setTimeout(waitDown, interval);
        } else {
          if (status) {
            status.textContent = 'Device is down, waiting for it to come back...';
          }
          setTimeout(waitUp, interval);
        }
      }).catch(function () {
        if (status) {
          status.textContent = 'Device is down, waiting for it to come back...';
        }
        setTimeout(waitUp, interval);
      });
    }

    function waitUp() {
      if (Date.now() - start > timeout) {
        if (status) {
          status.textContent = 'Timeout - device did not respond within 2 minutes.';
          status.classList.add('is-error');
        }
        return;
      }
      fetch('/device-status').then(function (r) {
        if (r.ok) {
          window.location = returnTo || '/';
        } else {
          setTimeout(waitUp, interval);
        }
      }).catch(function () {
        setTimeout(waitUp, interval);
      });
    }

    setTimeout(waitDown, interval);
  }

  function initDynamicUI(root) {
    initProgressBars(root);
    startRebootOverlay(root);
  }

  document.addEventListener('DOMContentLoaded', function () {
    initCSRF();
    initDeviceStatusBanner();
    initDynamicUI(document);
  });

  if (window.htmx && document.body) {
    document.body.addEventListener('htmx:afterSwap', function (evt) {
      initDynamicUI(evt.target);
    });
  }
})();

// Dark mode toggle
(function() {
  function getTheme() {
    return document.cookie.split(';').map(c=>c.trim()).find(c=>c.startsWith('theme='))?.split('=')[1];
  }
  function setTheme(theme) {
    document.documentElement.classList.toggle('dark', theme === 'dark');
    document.cookie = 'theme=' + theme + '; path=/; max-age=31536000; samesite=lax';
    const btn = document.getElementById('theme-toggle');
    if (btn) btn.setAttribute('aria-pressed', theme === 'dark');
  }
  // Apply saved theme on load
  const saved = getTheme();
  if (saved) { setTheme(saved); }
  // Toggle on button click
  document.addEventListener('DOMContentLoaded', function() {
    const btn = document.getElementById('theme-toggle');
    if (btn) btn.addEventListener('click', function() {
      setTheme(document.documentElement.classList.contains('dark') ? 'light' : 'dark');
    });
  });
})();

// Sidebar toggle (mobile)
(function() {
  document.addEventListener('DOMContentLoaded', function() {
    var btn = document.getElementById('hamburger-btn');
    if (!btn) return;
    btn.addEventListener('click', function() {
      var open = document.body.classList.toggle('sidebar-open');
      btn.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
    // Close sidebar when clicking the overlay (::after pseudo)
    document.body.addEventListener('click', function(e) {
      if (document.body.classList.contains('sidebar-open') && e.target === document.body) {
        document.body.classList.remove('sidebar-open');
        btn.setAttribute('aria-expanded', 'false');
      }
    });
    // Close sidebar when a nav link is clicked (htmx navigation)
    document.addEventListener('htmx:beforeRequest', function() {
      if (document.body.classList.contains('sidebar-open')) {
        document.body.classList.remove('sidebar-open');
        if (btn) btn.setAttribute('aria-expanded', 'false');
      }
    });
  });
})();
