// ========== THEME MANAGEMENT ==========
function toggleTheme() {
    document.body.classList.toggle('dark');
    const icon = document.getElementById('theme-icon');
    if (icon) {
        icon.textContent = document.body.classList.contains('dark') ? '☀️' : '🌙';
    }
    localStorage.setItem('theme', document.body.classList.contains('dark') ? 'dark' : 'light');
}

function initTheme() {
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme === 'dark' || (!savedTheme && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
        document.body.classList.add('dark');
        const icon = document.getElementById('theme-icon');
        if (icon) {
            icon.textContent = '☀️';
        }
    }
}

function toggleMenu() {
    const navMenu = document.getElementById('navMenu');
    if (navMenu) {
        navMenu.classList.toggle('active');
    }
}

function openImage(src) {
  window.open(src, '_blank');
}

async function logout() {
    const confirmed = await showDialog({
        type: 'warning',
        title: 'Confirm Logout',
        subtitle: 'Are you sure?',
        message: 'Are you sure you want to logout from your account?',
        confirmText: 'Logout',
        cancelText: 'Cancel'
    });

    if (confirmed) {
        try {
            await fetch('/api/logout', { method: 'POST' });
            showNotification({
                type: 'success',
                title: 'Logged Out',
                message: 'You have been successfully logged out',
                duration: 2000
            });
            setTimeout(() => {
                window.location.href = '/login';
            }, 500);
        } catch (error) {
            showNotification({
                type: 'error',
                title: 'Logout Failed',
                message: 'An error occurred while logging out',
                duration: 3000
            });
        }
    }
}

// ========== NOTIFICATION SYSTEM ==========
function showNotification(options) {
  const container = getNotificationContainer();

  const icons = {
    success: '✅',
    error: '❌',
    warning: '⚠️',
    info: 'ℹ️'
  };

  const notification = document.createElement('div');
  notification.className = `notification ${options.type}`;
  notification.innerHTML = `
    <div class="notification-icon">${icons[options.type]}</div>
    <div class="notification-content">
      <div class="notification-title">${options.title}</div>
      <div class="notification-message">${options.message}</div>
    </div>
    <button class="notification-close" onclick="closeNotification(this)">✕</button>
    <div class="notification-progress"></div>
  `;

  container.appendChild(notification);

  const duration = options.duration || 5000;
  const progress = notification.querySelector('.notification-progress');
  progress.style.width = '100%';
  progress.style.transition = `width ${duration}ms linear`;

  setTimeout(() => {
    progress.style.width = '0%';
  }, 10);

  setTimeout(() => {
    closeNotification(notification.querySelector('.notification-close'));
  }, duration);
}

function getNotificationContainer() {
  let container = document.querySelector('.notification-container');
  if (!container) {
    container = document.createElement('div');
    container.className = 'notification-container';
    document.body.appendChild(container);
  }
  return container;
}

function closeNotification(button) {
  const notification = button.closest('.notification');
  if (notification) {
      notification.classList.add('hiding');
      setTimeout(() => notification.remove(), 300);
  }
}

// ========== DIALOG SYSTEM ==========
function showDialog(options) {
  return new Promise((resolve) => {
    const overlay = document.createElement('div');
    overlay.className = 'dialog-overlay';

    const icons = {
      success: '✅',
      error: '❌',
      warning: '⚠️',
      info: 'ℹ️'
    };

    const isDanger = options.type === 'error' || options.danger;

    overlay.innerHTML = `
      <div class="dialog ${options.type}">
        <div class="dialog-header">
          <div class="dialog-icon">${icons[options.type]}</div>
          <div class="dialog-header-content">
            <div class="dialog-title">${options.title}</div>
            ${options.subtitle ? `<div class="dialog-subtitle">${options.subtitle}</div>` : ''}
          </div>
        </div>
        <div class="dialog-body">${options.message}</div>
        <div class="dialog-footer">
          <button class="dialog-btn cancel">${options.cancelText || 'Cancel'}</button>
          <button class="dialog-btn confirm ${isDanger ? 'danger' : ''}">${options.confirmText || 'Confirm'}</button>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    const cancelBtn = overlay.querySelector('.cancel');
    const confirmBtn = overlay.querySelector('.confirm');

    function closeDialog(result) {
      overlay.classList.add('hiding');
      setTimeout(() => {
        overlay.remove();
        resolve(result);
      }, 200);
    }

    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) closeDialog(false);
    });

    cancelBtn.addEventListener('click', () => closeDialog(false));
    confirmBtn.addEventListener('click', () => closeDialog(true));
  });
}

// ========== LOADING STATES ==========
function setLoadingState(button, loading, originalText = 'Submit') {
    if (loading) {
        button.disabled = true;
        button.dataset.originalText = button.innerHTML;
        button.innerHTML = `<span class="spinner"></span> Loading...`;
    } else {
        button.disabled = false;
        button.innerHTML = button.dataset.originalText || originalText;
    }
}

// ========== PAGINATION HELPERS ==========
function createPagination(currentPage, totalPages, baseUrl, searchParams = {}) {
    if (totalPages <= 1) return '';
    
    let html = '<div class="pagination">';
    
    // Previous button
    if (currentPage > 1) {
        const params = new URLSearchParams({ ...searchParams, page: currentPage - 1 });
        html += `<a href="${baseUrl}?${params}" class="pagination-btn">← Previous</a>`;
    }
    
    // Page numbers
    const range = 2;
    for (let i = Math.max(1, currentPage - range); i <= Math.min(totalPages, currentPage + range); i++) {
        const params = new URLSearchParams({ ...searchParams, page: i });
        html += `<a href="${baseUrl}?${params}" class="pagination-btn ${i === currentPage ? 'active' : ''}">${i}</a>`;
    }
    
    // Next button
    if (currentPage < totalPages) {
        const params = new URLSearchParams({ ...searchParams, page: currentPage + 1 });
        html += `<a href="${baseUrl}?${params}" class="pagination-btn">Next →</a>`;
    }
    
    html += '</div>';
    return html;
}

// ========== SOCKET.IO WITH RECONNECTION ==========
let socket = null;
let reconnectAttempts = 0;
const maxReconnectAttempts = 10;
const reconnectDelay = 3000;

function initializeSocket() {
    if (typeof io === 'undefined') return;
    
    socket = io({
        reconnection: true,
        reconnectionDelay: reconnectDelay,
        reconnectionAttempts: maxReconnectAttempts,
        transports: ['websocket', 'polling']
    });
    
    socket.on('connect', () => {
        console.log('✅ Socket connected');
        
        // Show connection restored notification if it was a reconnection
        if (reconnectAttempts > 0) {
            showNotification({
                type: 'success',
                title: 'Connection Restored',
                message: 'You are back online!',
                duration: 2000
            });
        }
        
        reconnectAttempts = 0;
    });
    
    socket.on('disconnect', (reason) => {
        console.log('❌ Socket disconnected:', reason);
        
        if (reason === 'io server disconnect') {
            // Server disconnected, try to reconnect manually
            socket.connect();
        }
        
        showNotification({
            type: 'warning',
            title: 'Connection Lost',
            message: 'Attempting to reconnect...',
            duration: 3000
        });
    });
    
    socket.on('reconnect_attempt', (attempt) => {
        console.log(`🔄 Reconnection attempt ${attempt}/${maxReconnectAttempts}`);
        reconnectAttempts = attempt;
    });
    
    socket.on('reconnect_failed', () => {
        showNotification({
            type: 'error',
            title: 'Connection Failed',
            message: 'Could not reconnect to server. Please refresh the page.',
            duration: 5000
        });
    });
    
    socket.on('connect_error', (error) => {
        console.error('Socket connection error:', error);
    });
    
    return socket;
}

// ========== TYPING INDICATOR ==========
let typingTimeout = null;

function handleTyping(receiverId, isTyping) {
    if (!socket) return;
    
    socket.emit('typing', {
        receiver_id: receiverId,
        is_typing: isTyping
    });
}

function startTyping(receiverId) {
    handleTyping(receiverId, true);
    
    // Clear previous timeout
    if (typingTimeout) {
        clearTimeout(typingTimeout);
    }
    
    // Stop typing after 3 seconds of inactivity
    typingTimeout = setTimeout(() => {
        handleTyping(receiverId, false);
    }, 3000);
}

function stopTyping(receiverId) {
    if (typingTimeout) {
        clearTimeout(typingTimeout);
        typingTimeout = null;
    }
    handleTyping(receiverId, false);
}

// ========== UTILITY FUNCTIONS ==========
function escapeHtml(text) {
    if (typeof text !== 'string') return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatTimeAgo(isoTimestamp) {
    if (!isoTimestamp) return 'Just now';
    
    try {
        // Parse the timestamp (assume it's in local timezone from server)
        const msgDate = new Date(isoTimestamp.replace(' ', 'T'));
        const now = new Date();
        
        // Calculate difference in seconds
        const diffMs = now - msgDate;
        const diffSecs = Math.floor(diffMs / 1000);
        
        // Handle future dates (clock skew)
        if (diffSecs < 0) return 'Just now';
        
        // Less than 10 seconds
        if (diffSecs < 10) return 'Just now';
        
        // Less than 60 seconds
        if (diffSecs < 60) return `${diffSecs}s ago`;
        
        // Less than 60 minutes
        const diffMins = Math.floor(diffSecs / 60);
        if (diffMins < 60) return `${diffMins}m ago`;
        
        // Less than 24 hours
        const diffHours = Math.floor(diffMins / 60);
        if (diffHours < 24) return `${diffHours}h ago`;
        
        // Less than 7 days
        const diffDays = Math.floor(diffHours / 24);
        if (diffDays < 7) return `${diffDays}d ago`;
        
        // Less than 30 days
        if (diffDays < 30) {
            const weeks = Math.floor(diffDays / 7);
            return `${weeks}w ago`;
        }
        
        // More than 30 days - show date
        const options = { month: 'short', day: 'numeric' };
        if (msgDate.getFullYear() !== now.getFullYear()) {
            options.year = 'numeric';
        }
        return msgDate.toLocaleDateString('en-US', options);
        
    } catch (e) {
        console.error('Time format error:', e);
        return 'Just now';
    }
}

function updateMessageTimes() {
    document.querySelectorAll('.message-time[data-timestamp]').forEach(el => {
        const timestamp = el.getAttribute('data-timestamp');
        if (timestamp) el.textContent = formatTimeAgo(timestamp);
    });
}

function scrollToBottom() {
    setTimeout(() => {
        const container = document.getElementById('messagesContainer');
        if (container) {
            container.scrollTop = container.scrollHeight;
        }
    }, 50);
}

// ========== DEBOUNCE HELPER ==========
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    
    // Initialize socket if io is available
    if (typeof io !== 'undefined') {
        initializeSocket();
    }
    
    // Update time-ago elements every 15 seconds
    setInterval(() => {
        document.querySelectorAll('[data-timestamp]').forEach(el => {
            const timestamp = el.getAttribute('data-timestamp');
            if (timestamp) {
                el.textContent = formatTimeAgo(timestamp);
            }
        });
    }, 15000);
});

// Auto-reconnect on window focus (if disconnected)
window.addEventListener('focus', () => {
    if (socket && !socket.connected) {
        console.log('🔄 Window focused, attempting reconnection...');
        socket.connect();
    }
});