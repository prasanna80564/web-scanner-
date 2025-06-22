document.addEventListener('DOMContentLoaded', () => {
  const countEl = document.getElementById('count');
  const statusEl = document.getElementById('status');
  const clearBtn = document.getElementById('clearBtn');
  const viewAllBtn = document.getElementById('viewAllBtn');
  const toggle = document.getElementById('monitoringToggle');

  
  chrome.runtime.sendMessage({ type: 'get_vulnerabilities' }, (vulnerabilities) => {
    updateCount(vulnerabilities?.length || 0);
  });

  chrome.runtime.sendMessage({ type: 'get_monitoring_status' }, (response) => {
    if (chrome.runtime.lastError) {
      console.error(chrome.runtime.lastError);
      return;
    }
    toggle.checked = response?.isMonitoring ?? true;
    updateStatus(response?.isMonitoring ?? true);
  });

 
  toggle.addEventListener('change', () => {
    chrome.runtime.sendMessage({ type: 'toggle_monitoring' }, (response) => {
      if (chrome.runtime.lastError) {
        console.error(chrome.runtime.lastError);
        return;
      }
      updateStatus(response.isMonitoring);
    });
  });


  viewAllBtn.addEventListener('click', () => {
    chrome.tabs.create({
      url: chrome.runtime.getURL('pages/vulnerabilities.html')
    }).catch(err => console.error('Error opening tab:', err));
  });

  
  clearBtn.addEventListener('click', () => {
    if (confirm('Are you sure you want to clear all findings?')) {
      chrome.runtime.sendMessage({ type: 'clear_vulnerabilities' }, () => {
        if (chrome.runtime.lastError) {
          console.error(chrome.runtime.lastError);
          return;
        }
        updateCount(0);
      });
    }
  });

  function updateCount(count) {
    countEl.textContent = count;
    countEl.style.color = count > 0 ? 'var(--danger)' : 'var(--text-light)';
  }

  function updateStatus(isMonitoring) {
    if (isMonitoring) {
      statusEl.textContent = 'Active';
      statusEl.className = 'status status-active';
    } else {
      statusEl.textContent = 'Paused';
      statusEl.className = 'status status-paused';
    }
  }

 
  chrome.runtime.onMessage.addListener((request) => {
    if (request.type === 'new_vulnerability') {
      chrome.runtime.sendMessage({ type: 'get_vulnerabilities' }, (vulnerabilities) => {
        updateCount(vulnerabilities?.length || 0);
      });
    }
  });
});