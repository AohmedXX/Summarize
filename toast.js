/**
 * Toast Notification System
 * عرض الرسائل داخل الموقع بدل من alert المتصفح
 */

class ToastManager {
    constructor() {
        this.createContainer();
    }

    createContainer() {
        // تحقق من وجود الـ container
        if (document.getElementById('toast-container')) return;
        
        const container = document.createElement('div');
        container.id = 'toast-container';
        container.className = 'fixed top-0 left-0 right-0 z-[9999] pointer-events-none p-4 flex flex-col gap-2';
        container.style.direction = 'rtl';
        document.body.appendChild(container);
    }

    show(message, type = 'info', duration = 4000) {
        this.createContainer();
        const container = document.getElementById('toast-container');
        
        // تحديد الألوان حسب نوع الرسالة
        const colors = {
            'success': {
                bg: 'bg-green-500',
                icon: 'check-circle',
                border: 'border-green-600'
            },
            'error': {
                bg: 'bg-red-500',
                icon: 'alert-circle',
                border: 'border-red-600'
            },
            'warning': {
                bg: 'bg-yellow-500',
                icon: 'alert-triangle',
                border: 'border-yellow-600'
            },
            'info': {
                bg: 'bg-blue-500',
                icon: 'info',
                border: 'border-blue-600'
            }
        };

        const config = colors[type] || colors['info'];
        
        const toast = document.createElement('div');
        toast.className = `${config.bg} text-white px-6 py-4 rounded-xl shadow-xl pointer-events-auto animate-fade-in-up max-w-md w-full md:min-w-[400px] flex items-center gap-3 border-l-4 ${config.border}`;
        toast.innerHTML = `
            <i data-lucide="${config.icon}" class="h-5 w-5 flex-shrink-0"></i>
            <span class="text-sm md:text-base font-medium flex-1">${message}</span>
            <button class="text-white hover:bg-white/20 p-1 rounded transition" onclick="this.parentElement.remove()">
                <i data-lucide="x" class="h-4 w-4"></i>
            </button>
        `;
        
        container.appendChild(toast);
        
        // تحديث الأيقونات
        if (typeof lucide !== 'undefined') {
            lucide.createIcons();
        }
        
        // إزالة الرسالة تلقائياً بعد المدة المحددة
        if (duration > 0) {
            setTimeout(() => {
                toast.style.animation = 'fadeOutDown 300ms ease-in forwards';
                setTimeout(() => toast.remove(), 300);
            }, duration);
        }
    }

    success(message, duration = 4000) {
        this.show(message, 'success', duration);
    }

    error(message, duration = 4000) {
        this.show(message, 'error', duration);
    }

    warning(message, duration = 4000) {
        this.show(message, 'warning', duration);
    }

    info(message, duration = 4000) {
        this.show(message, 'info', duration);
    }
}

// إنشاء مثيل عام
const toast = new ToastManager();

// إضافة أنيميشن fadeOutDown
if (!document.querySelector('style[data-toast]')) {
    const style = document.createElement('style');
    style.setAttribute('data-toast', 'true');
    style.textContent = `
        @keyframes fadeOutDown {
            0% { opacity: 1; transform: translateY(0); }
            100% { opacity: 0; transform: translateY(10px); }
        }
        
        @keyframes fadeInUp {
            0% { opacity: 0; transform: translateY(8px); }
            100% { opacity: 1; transform: translateY(0); }
        }
        
        .animate-fade-in-up {
            animation: fadeInUp 300ms ease-out both;
        }
    `;
    document.head.appendChild(style);
}
