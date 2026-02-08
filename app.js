// --------------------------------------------------------------------------
// � Local Storage Only - No Backend/Firebase
// --------------------------------------------------------------------------

// This application uses localStorage exclusively.
// All data is stored locally on the user's device.

// --------------------------------------------------------------------------
// 🔒 Security & Protection Layer
// --------------------------------------------------------------------------

// ⚠️ IMPORTANT SECURITY NOTES:
// This is a CLIENT-SIDE ONLY application with localStorage-based storage.
// Current limitations & recommendations for production:
// 1. Passwords: NEVER store plain text passwords - use bcrypt/argon2 on server
// 2. Authentication: Implement JWT tokens with secure httpOnly cookies
// 3. Data Encryption: Encrypt sensitive data in localStorage
// 4. HTTPS: Always use HTTPS in production
// 5. CORS: Implement proper CORS policies
// 6. Rate Limiting: Implement server-side rate limiting
// 7. Content Security Policy: Configure proper CSP headers
// 8. Input Validation: Validate on BOTH client and server
// 9. File Upload: Scan files server-side with antivirus
// 10. Database: Use proper SQL injection prevention & parameterized queries

const security = {
    // Sanitize HTML to prevent XSS attacks
    sanitizeHTML: (str) => {
        if (!str) return '';
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;',
            '/': '&#x2F;'
        };
        return String(str).replace(/[&<>"'\/]/g, s => map[s]);
    },

    // Sanitize input text: remove dangerous patterns
    sanitizeInput: (str) => {
        if (!str) return '';
        str = String(str).trim();
        // Remove potentially dangerous JavaScript patterns
        str = str.replace(/<script[^>]*>.*?<\/script>/gi, '');
        str = str.replace(/javascript:/gi, '');
        str = str.replace(/on\w+\s*=/gi, '');
        str = str.replace(/eval\s*\(/gi, '');
        str = str.replace(/expression\s*\(/gi, '');
        return security.sanitizeHTML(str);
    },

    // Check for XSS attempts
    hasXSSPatterns: (str) => {
        const xssPatterns = [
            /<script/i,
            /javascript:/i,
            /on\w+\s*=/i,
            /eval\s*\(/i,
            /<iframe/i,
            /<object/i,
            /<embed/i,
            /expression\s*\(/i,
            /vbscript:/i
        ];
        return xssPatterns.some(pattern => pattern.test(str));
    },

    // Validate email format
    validateEmail: (email) => {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    },

    // Validate password strength
    validatePassword: (password) => {
        // Min 6 chars, at least one letter and one number
        const hasMinLength = password.length >= 6;
        const hasLetter = /[a-zA-Z]/.test(password);
        const hasNumber = /\d/.test(password);
        return {
            valid: hasMinLength && hasLetter && hasNumber,
            score: (hasMinLength ? 1 : 0) + (hasLetter ? 1 : 0) + (hasNumber ? 1 : 0)
        };
    },

    // Validate file type
    validFileTypes: ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/vnd.ms-powerpoint', 'application/vnd.openxmlformats-officedocument.presentationml.presentation', 'text/plain'],
    validFileExtensions: ['pdf', 'doc', 'docx', 'ppt', 'pptx', 'txt'],
    
    isValidFileType: (file) => {
        if (!file) return false;
        const isValidMime = security.validFileTypes.includes(file.type);
        const ext = file.name.split('.').pop().toLowerCase();
        const isValidExt = security.validFileExtensions.includes(ext);
        return isValidMime && isValidExt;
    },

    // Validate file size (max 50MB)
    isValidFileSize: (file, maxMB = 50) => {
        return file.size <= maxMB * 1024 * 1024;
    },

    // Rate limiting - prevent brute force attacks
    rateLimitMap: {},
    checkRateLimit: (key, maxAttempts = 5, windowMs = 60000) => {
        const now = Date.now();
        if (!security.rateLimitMap[key]) {
            security.rateLimitMap[key] = [];
        }
        // Remove old attempts outside window
        security.rateLimitMap[key] = security.rateLimitMap[key].filter(t => now - t < windowMs);
        
        if (security.rateLimitMap[key].length >= maxAttempts) {
            return false; // Rate limit exceeded
        }
        security.rateLimitMap[key].push(now);
        return true;
    },

    // Input length validation
    validateLength: (str, min = 1, max = 500) => {
        const len = String(str).length;
        return len >= min && len <= max;
    },

    // Validate username/name
    validateUsername: (name) => {
        // Only alphanumeric, spaces, hyphens
        const nameRegex = /^[a-zA-Z\u0600-\u06FF\s\-']{2,}$/;
        return nameRegex.test(name);
    },

    // Secure data - never expose sensitive info in errors
    createSecureError: (publicMsg) => {
        console.log('Security Event:', publicMsg); // Log server-side equivalent
        return publicMsg;
    }
};

// --------------------------------------------------------------------------
// القاموس (Localization) - كما هو بدون تغيير
// --------------------------------------------------------------------------
const dictionary = {
    ar: {
        siteName: "Summarize",
        browse: "تصفح الملفات",
        upload: "رفع ملف",
        login: "تسجيل الدخول",
        register: "إنشاء حساب",
        logout: "تسجيل خروج",
        admin: "لوحة التحكم",
        welcome: "مرحباً،",
        heroTitle: "كل ما تحتاجه من",
        heroHighlight: "تلخيصات ومذكرات",
        heroDesc: "منصة Summarize تتيح لك الوصول السريع والسهل إلى آلاف الملفات الدراسية الموثوقة. حمل وشارك المعرفة.",
        searchPlaceholder: "ابحث عن اسم المادة، المحاضرة، أو الدكتور...",
        latestFiles: "أحدث الملفات المضافة",
        filter: "تصفية",
        loading: "جاري تحميل الملفات...",
        download: "تحميل الملف",
        footer: "© 2026 Summarize. جميع الحقوق محفوظة.",
        uploadTitle: "رفع ملف جديد",
        uploadDesc: "شارك ملخصاتك ومذكراتك مع زملائك بسهولة.",
        fileTitle: "عنوان الملف",
        subject: "المادة الدراسية",
        fileType: "نوع الملف",
        pageCount: "عدد الصفحات",
        selectFile: "اختر ملفاً",
        orDrag: "أو اسحبه هنا",
        submitUpload: "رفع الملف",
        uploading: "جاري الرفع...",
        successUpload: "تم رفع الملف بنجاح!",
        author: "المؤلف الأصلي",
        description: "الوصف",
        uploadedBy: "رفع بواسطة",
        cardDate: "التاريخ",
        cardSize: "الحجم",
        cardDownloads: "التحميلات",
        cardUploadedBy: "المرفوع بواسطة",
        viewMore: "عرض المزيد",
        unknown: "مجهول",
        fileNotFound: "الملف غير موجود",
        downloadStarted: "جاري التحميل!",
        files: "ملفات",
        fileNotAvailable: "بيانات الملف غير متاحة للتحميل",
        downloadError: "خطأ في تحميل الملف",
        typeSummary: "ملخص",
        typeNote: "مذكرة",
        typeExam: "امتحان سابق",
        typeProject: "مشروع",
        loginTitle: "تسجيل الدخول",
        noAccount: "أو",
        createAccountLink: "أنشئ حساباً جديداً",
        email: "البريد الإلكتروني",
        password: "كلمة المرور",
        rememberMe: "تذكرني",
        forgotPassword: "نسيت كلمة المرور؟",
        registerTitle: "إنشاء حساب جديد",
        haveAccount: "لديك حساب بالفعل؟",
        loginLink: "تسجيل الدخول",
        fullName: "الاسم الكامل",
        confirmPassword: "تأكيد كلمة المرور",
        mustLoginToDownload: "يجب تسجيل الدخول لتحميل الملف",
        passwordMismatch: "كلمتا المرور غير متطابقتين",
        files: "الملفات",
        users: "المستخدمين",
        adminTitle: "قاعدة البيانات (Admin)",
        backHome: "العودة للرئيسية",
        dangerZone: "منطقة الخطر",
        clearData: "حذف جميع البيانات",
        registeredUsers: "المستخدمون المسجلون",
        uploadedFiles: "الملفات المرفوعة",
        noUsers: "لا يوجد مستخدمين مسجلين",
        noFiles: "لا توجد ملفات مرفوعة",
        confirmClear: "هل أنت متأكد من حذف جميع المستخدمين والملفات؟",
        date: "التاريخ",
        size: "الحجم",
        reviewQueue: "قائمة المراجعة",
        pendingReview: "الملف سيكون قيد المراجعة من قبل المشرفين قبل نشره",
        approve: "قبول",
        reject: "رفض",
        contact: "تواصل",
        contactTitle: "تواصل مع المسؤول",
        message: "رسالتك",
        sendMessage: "إرسال",
        messageSent: "تم إرسال الرسالة",
        filterType: "نوع الملف",
        filterSubject: "المادة",
        clearFilters: "إزالة التصفية",
        success: "تم بنجاح",
        selectAll: "تحديد الكل",
        deleteSelected: "حذف المحدد",
        editSelected: "تعديل المحدد",
        userEdited: "تم تعديل المستخدم",
        fileEdited: "تم تعديل الملف",
        chooseOne: "برجاء اختيار عنصر واحد فقط للتعديل",
        newFilesAlert: "تم إضافة ملفات جديدة منذ زيارتك الأخيرة!",
        viewDetails: "عرض التفاصيل",
        close: "إغلاق",
        downloads: "تحميل",
        view: "عرض",
        preview: "معاينة",
        role: "الدور",
        userId: "معرف المستخدم",
        avatar: "الصورة",
        userDetails: "معلومات المستخدم",
        filePreview: "معاينة الملف",
        noAttachment: "لا يوجد ملف للعرض",
        loading: "جاري التحميل...",
        fileNotFound: "لم يتم العثور على المحتوى المرفق",
        fileSizeExceeded: "حجم الملف أكبر من الحد المسموح للمعاينة",
        downloadFile: "تحميل الملف",
        downloadImage: "تحميل الصورة",
        downloadPdf: "تحميل PDF",
        fileType: "نوع الملف",
        userNotFound: "المستخدم غير موجود",
        profile: "الملف الشخصي",
        avatarHint: "صيغ مدعومة: JPG, PNG. سيتم حفظ الصورة محلياً فقط.",
        save: "حفظ",
        cancel: "إلغاء",
        invalidName: "الاسم: حروف وأرقام فقط (الحد الأدنى حرفين)",
        invalidEmail: "البريد الإلكتروني غير صحيح",
        unsafeContent: "محتوى غير آمن",
        mustLoginFirst: "يجب تسجيل الدخول أولاً",
        emailAlreadyInUse: "هذا البريد مستخدم بالفعل",
        changesSaved: "تم حفظ التغييرات"
    },
    en: {
        siteName: "Summarize",
        browse: "Browse Files",
        upload: "Upload File",
        login: "Login",
        register: "Register",
        logout: "Logout",
        admin: "Dashboard",
        welcome: "Welcome,",
        heroTitle: "Everything you need from",
        heroHighlight: "Summaries & Notes",
        heroDesc: "Summarize platform gives you fast and easy access to thousands of reliable study files. Download and share knowledge.",
        searchPlaceholder: "Search for subject, lecture, or professor...",
        latestFiles: "Latest Added Files",
        filter: "Filter",
        loading: "Loading files...",
        download: "Download File",
        footer: "© 2026 Summarize. All rights reserved.",
        uploadTitle: "Upload New File",
        uploadDesc: "Share your summaries and notes with colleagues easily.",
        fileTitle: "File Title",
        subject: "Subject",
        fileType: "File Type",
        pageCount: "Page Count",
        selectFile: "Choose a file",
        orDrag: "or drag it here",
        submitUpload: "Upload File",
        uploading: "Uploading...",
        successUpload: "File uploaded successfully!",
        author: "Original Author",
        description: "Description",
        uploadedBy: "Uploaded by",
        cardDate: "Date",
        cardSize: "Size",
        cardDownloads: "Downloads",
        cardUploadedBy: "Uploaded by",
        viewMore: "View More",
        unknown: "Unknown",
        fileNotFound: "File not found",
        downloadStarted: "Download started!",
        files: "Files",
        fileNotAvailable: "File data not available for download",
        downloadError: "Error downloading file",
        typeSummary: "Summary",
        typeNote: "Note",
        typeExam: "Past Exam",
        typeProject: "Project",
        loginTitle: "Login",
        noAccount: "Or",
        createAccountLink: "create a new account",
        email: "Email Address",
        password: "Password",
        rememberMe: "Remember me",
        forgotPassword: "Forgot password?",
        registerTitle: "Create New Account",
        haveAccount: "Already have an account?",
        loginLink: "Login",
        fullName: "Full Name",
        confirmPassword: "Confirm Password",
        passwordMismatch: "Passwords do not match",
        files: "Files",
        users: "Users",
        adminTitle: "Database (Admin)",
        backHome: "Back to Home",
        dangerZone: "Danger Zone",
        clearData: "Delete All Data",
        registeredUsers: "Registered Users",
        uploadedFiles: "Uploaded Files",
        noUsers: "No registered users",
        noFiles: "No uploaded files",
        confirmClear: "Are you sure you want to delete all users and files?",
        date: "Date",
        size: "Size",
        reviewQueue: "Review Queue",
        pendingReview: "Your file will be under review by administrators before publishing",
        approve: "Approve",
        reject: "Reject",
        contact: "Contact",
        contactTitle: "Contact Administrator",
        message: "Your Message",
        sendMessage: "Send",
        messageSent: "Message sent",
        filterType: "File Type",
        filterSubject: "Subject",
        clearFilters: "Clear Filters",
        irreversibleWarning: "These actions cannot be undone.",
        success: "Success",
        selectAll: "Select All",
        deleteSelected: "Delete Selected",
        editSelected: "Edit Selected",
        userEdited: "User updated",
        fileEdited: "File updated",
        chooseOne: "Please select exactly one item to edit",
        newFilesAlert: "New files added since last visit!",
        viewDetails: "View Details",
        close: "Close",
        mustLoginToDownload: "You must be logged in to download files",
        downloads: "Downloads",
        view: "View",
        preview: "Preview",
        role: "Role",
        userId: "User ID",
        avatar: "Avatar",
        userDetails: "User Details",
        filePreview: "File Preview",
        noAttachment: "No file to preview",
        loading: "Loading...",
        fileNotFound: "Content not found",
        fileSizeExceeded: "File size exceeds preview limit",
        downloadFile: "Download File",
        downloadImage: "Download Image",
        downloadPdf: "Download PDF",
        fileType: "File Type",
        userNotFound: "User not found",
        profile: "Profile",
        avatarHint: "Supported formats: JPG, PNG. Image will be saved locally only.",
        save: "Save",
        cancel: "Cancel",
        invalidName: "Name: letters and spaces only (min 2 chars)",
        invalidEmail: "Invalid email address",
        unsafeContent: "Invalid input",
        mustLoginFirst: "Must login first",
        emailAlreadyInUse: "Email already in use",
        changesSaved: "Changes saved"
    }
};

// --------------------------------------------------------------------------
// إدارة السمات واللغات (Theme & Language Manager)
// --------------------------------------------------------------------------
class AppManager {
    constructor() {
        this.lang = localStorage.getItem('summarize_lang') || 'ar';
        this.theme = localStorage.getItem('summarize_theme') || 'light';
    }

    init() {
        this.applyTheme();
        this.applyLanguage();
        this.checkNewFiles();
        updateAuthUI();
    }

    checkNewFiles() {
        const lastVisit = localStorage.getItem('summarize_last_visit');
        const now = Date.now();
        localStorage.setItem('summarize_last_visit', now);
    }

    toggleTheme() {
        this.theme = this.theme === 'light' ? 'dark' : 'light';
        localStorage.setItem('summarize_theme', this.theme);
        this.applyTheme();
    }

    toggleLanguage() {
        this.lang = this.lang === 'ar' ? 'en' : 'ar';
        localStorage.setItem('summarize_lang', this.lang);
        this.applyLanguage();
        updateAuthUI();
    }

    applyTheme() {
        if (this.theme === 'dark') {
            document.documentElement.classList.add('dark');
        } else {
            document.documentElement.classList.remove('dark');
        }
    }

    applyLanguage() {
        document.documentElement.lang = this.lang;
        document.documentElement.dir = this.lang === 'ar' ? 'rtl' : 'ltr';
        document.body.dir = this.lang === 'ar' ? 'rtl' : 'ltr';
        document.body.lang = this.lang;
        
        document.querySelectorAll('[data-i18n]').forEach(el => {
            const key = el.getAttribute('data-i18n');
            const langDict = dictionary[this.lang];
            
            if (langDict && langDict[key]) {
                const text = langDict[key];
                
                if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') {
                    el.placeholder = text;
                } else if (el.tagName === 'BUTTON' || el.tagName === 'A') {
                    el.textContent = text;
                } else {
                    el.textContent = text;
                }
                
                el.classList.remove('lang-ar', 'lang-en');
                el.classList.add(`lang-${this.lang}`);
            }
        });
        
        // Dispatch event for pages to update dynamic content
        document.dispatchEvent(new CustomEvent('appLanguageChanged', { detail: { lang: this.lang } }));
    }

    t(key) { return dictionary[this.lang][key] || key; }

    translateFileType(type) {
        const typeMap = {
            'ar': {
                'ملخص': '📚 ملخص',
                'مذكرة': '📝 مذكرة',
                'امتحان سابق': '📋 امتحان سابق',
                'مشروع': '🎯 مشروع'
            },
            'en': {
                'ملخص': '📚 Summary',
                'مذكرة': '📝 Note',
                'امتحان سابق': '📋 Past Exam',
                'مشروع': '🎯 Project'
            }
        };
        return typeMap[this.lang]?.[type] || type;
    }
}

// --------------------------------------------------------------------------
// نظام المصادقة (Auth System)
// --------------------------------------------------------------------------
const auth = {
    getCurrentUser: () => JSON.parse(localStorage.getItem('currentUser')),
    isAuthenticated: () => !!localStorage.getItem('currentUser'),
    isAdmin: () => {
        const user = JSON.parse(localStorage.getItem('currentUser'));
        return user && (user.role === 'admin' || user.email === "ahmed@summarize.com");
    },
    logout: () => {
        localStorage.removeItem('currentUser');
        window.location.href = 'index.html';
    },
    initAdmin: () => {
        let users = JSON.parse(localStorage.getItem('users') || '[]');
        const adminEmail = "ahmed@summarize.com";
        if (users.find(u => u.email === adminEmail)) return;

        const adminUser = {
            id: 'admin_001',
            name: "Ahmed (Owner)",
            email: adminEmail,
            password: "2008.",
            role: 'admin',
            createdAt: new Date().toISOString()
        };
        users.push(adminUser);
        localStorage.setItem('users', JSON.stringify(users));
    }
};

auth.initAdmin();

window.auth = auth;
const appManager = new AppManager();
window.appManager = appManager;

// تحديث واجهة المستخدم بناءً على حالة تسجيل الدخول
function updateAuthUI() {
    const navAuthSection = document.getElementById('authSection');
    if (!navAuthSection) return;

    if (auth.isAuthenticated()) {
        const user = auth.getCurrentUser();
        const isAdmin = auth.isAdmin();
        // build avatar display (image or initials)
        // Show profile image in navbar only after the user has uploaded at least one file (either approved in `files` or pending in `review`).
        let avatarHTML = '';
        try {
            const allFiles = JSON.parse(localStorage.getItem('files') || '[]');
            const reviewQueue = JSON.parse(localStorage.getItem('review') || '[]');
            const hasUploaded = allFiles.concat(reviewQueue).some(f => String(f.uploadedBy) === String(user.email));

            if (user && user.avatar) {
                avatarHTML = `<a href="profile.html" title="${user.name || ''}"><img src="${user.avatar}" alt="avatar" class="h-8 w-8 rounded-full object-cover border-2 border-white dark:border-gray-800"></a>`;
            } else {
                const initials = user && user.name ? user.name.split(/\s+/).map(p=>p[0]).slice(0,2).join('') : 'U';
                avatarHTML = `<a href="profile.html" title="${user.name || ''}" class="h-8 w-8 rounded-full bg-indigo-600 text-white flex items-center justify-center font-semibold">${initials}</a>`;
            }
        } catch(e) { avatarHTML = `<a href="profile.html" class="h-8 w-8 rounded-full bg-indigo-600 text-white flex items-center justify-center font-semibold">U</a>` }

        navAuthSection.innerHTML = `
            <div class="flex items-center gap-4">
                ${isAdmin ? `
                <a href="admin.html" class="text-indigo-600 font-bold dark:text-indigo-400 flex items-center gap-1">
                    <i data-lucide="shield" class="h-4 w-4"></i> <span>${appManager.t('admin')}</span>
                </a>` : ''}
                <a href="upload.html" class="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition flex items-center gap-2">
                    <i data-lucide="upload" class="h-4 w-4"></i> <span>${appManager.t('upload')}</span>
                </a>
                <a href="profile.html" class="flex items-center gap-3">
                    ${avatarHTML}
                </a>
                <button onclick="auth.logout()" class="text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20 px-3 py-2 rounded-md transition text-sm font-medium">
                    ${appManager.t('logout')}
                </button>
            </div>
        `;
    } else {
        navAuthSection.innerHTML = `
            <div class="flex items-center gap-3">
                <a href="login.html" class="text-gray-600 hover:text-blue-600 dark:text-gray-300 px-3 py-2 transition font-medium">${appManager.t('login')}</a>
                <a href="register.html" class="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition">${appManager.t('register')}</a>
            </div>
        `;
    }
    if (typeof lucide !== 'undefined') lucide.createIcons();
}

document.addEventListener('DOMContentLoaded', () => {
    appManager.init();
});

// --------------------------------------------------------------------------
// عرض الملفات على الصفحة الرئيسية (Display Files)
// --------------------------------------------------------------------------
function fetchFiles() {
    const filesGrid = document.getElementById('filesGrid');
    if (!filesGrid) return;

    const files = JSON.parse(localStorage.getItem('files') || '[]');
    const users = JSON.parse(localStorage.getItem('users') || '[]');
    
    if (files.length === 0) {
        filesGrid.innerHTML = `
            <div class="col-span-full text-center py-12">
                <p class="text-gray-500 dark:text-gray-400" data-i18n="noFiles">${appManager.t('noFiles')}</p>
            </div>
        `;
        return;
    }

    const filesByType = {
        'ملخص': [],
        'مذكرة': [],
        'امتحان سابق': [],
        'مشروع': []
    };

    files.forEach(file => {
        if (filesByType[file.type]) {
            filesByType[file.type].push(file);
        }
    });

    const typeConfig = {
        'ملخص': { 
            en: 'Summary', 
            color: 'bg-blue-50 dark:bg-blue-900/20 border-blue-200 dark:border-blue-800',
            icon: 'book-open',
            iconColor: 'text-blue-600 dark:text-blue-400',
            titleColor: 'text-blue-700 dark:text-blue-200',
            badge: 'bg-gradient-to-r from-blue-100 to-blue-50 dark:from-blue-900/40 text-blue-800 dark:text-blue-300'
        },
        'مذكرة': { 
            en: 'Notes', 
            color: 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800',
            icon: 'notebook',
            iconColor: 'text-green-600 dark:text-green-400',
            titleColor: 'text-green-700 dark:text-green-200',
            badge: 'bg-gradient-to-r from-green-100 to-green-50 dark:from-green-900/40 text-green-800 dark:text-green-300'
        },
        'امتحان سابق': { 
            en: 'Past Exams', 
            color: 'bg-orange-50 dark:bg-orange-900/20 border-orange-200 dark:border-orange-800',
            icon: 'clipboard-list',
            iconColor: 'text-orange-600 dark:text-orange-400',
            titleColor: 'text-orange-700 dark:text-orange-200',
            badge: 'bg-gradient-to-r from-orange-100 to-orange-50 dark:from-orange-900/40 text-orange-800 dark:text-orange-300'
        },
        'مشروع': { 
            en: 'Projects', 
            color: 'bg-purple-50 dark:bg-purple-900/20 border-purple-200 dark:border-purple-800',
            icon: 'briefcase',
            iconColor: 'text-purple-600 dark:text-purple-400',
            titleColor: 'text-purple-700 dark:text-purple-200',
            badge: 'bg-gradient-to-r from-purple-100 to-purple-50 dark:from-purple-900/40 text-purple-800 dark:text-purple-300'
        }
    };

    let sectionsHTML = '';
    
    Object.entries(filesByType).forEach(([type, typeFiles]) => {
        if (typeFiles.length === 0) return;
        
        const config = typeConfig[type];
        const typeName = appManager.lang === 'ar' ? type : config.en;
        
        sectionsHTML += `
            <div class="mb-12 ${config.color} border rounded-2xl p-6">
                <div class="flex items-center gap-3 mb-8 pb-4 border-b-2 border-current border-opacity-20">
                    <i data-lucide="${config.icon}" class="h-8 w-8 ${config.iconColor}"></i>
                    <h2 class="text-3xl font-bold ${config.titleColor}">${typeName}</h2>
                    <span class="ml-auto px-4 py-2 rounded-full bg-white dark:bg-gray-800 text-sm font-semibold text-gray-700 dark:text-gray-300">${typeFiles.length} ${appManager.t('files')}</span>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    ${typeFiles.map(file => `
                        <div class="file-card group bg-white dark:bg-gray-800 rounded-2xl shadow-md hover:shadow-xl border border-gray-100 dark:border-gray-700 p-8 transition-all duration-300 hover:border-blue-300 dark:hover:border-blue-600 hover:-translate-y-1 ${appManager.lang === 'ar' ? 'rtl' : 'ltr'} lang-${appManager.lang}">
                            <div class="flex justify-between items-start mb-6">
                                <div class="flex-1">
                                    <div class="flex items-start gap-3 mb-3">
                                        <i data-lucide="file-text" class="h-6 w-6 text-blue-600 dark:text-blue-400 flex-shrink-0 mt-1"></i>
                                        <h3 class="text-xl font-bold text-gray-900 dark:text-white line-clamp-2">${security.sanitizeHTML(file.title)}</h3>
                                    </div>
                                    <div class="flex items-center gap-2 ${appManager.lang === 'ar' ? 'mr-9' : 'ml-9'}">
                                        <i data-lucide="book" class="h-4 w-4 text-purple-600 dark:text-purple-400"></i>
                                        <p class="text-sm font-medium text-gray-600 dark:text-gray-300">${security.sanitizeHTML(file.subject)}</p>
                                    </div>
                                </div>
                                <span class="px-4 py-2 rounded-full ${config.badge} text-xs font-semibold whitespace-nowrap ${appManager.lang === 'ar' ? 'mr-3' : 'ml-3'}">
                                    ${appManager.translateFileType ? appManager.translateFileType(file.type) : file.type}
                                </span>
                            </div>

                            <div class="grid grid-cols-3 gap-4 mb-6 pb-6 border-b border-gray-200 dark:border-gray-700">
                                <div class="flex items-center gap-3 bg-gray-50 dark:bg-gray-700/50 rounded-xl p-3">
                                    <i data-lucide="calendar" class="h-5 w-5 text-red-500 dark:text-red-400"></i>
                                    <div>
                                        <p class="text-xs text-gray-500 dark:text-gray-400 font-semibold" data-i18n="cardDate">${appManager.t('cardDate')}</p>
                                        <p class="text-sm font-bold text-gray-900 dark:text-white">${file.date}</p>
                                    </div>
                                </div>

                                <div class="flex items-center gap-3 bg-gray-50 dark:bg-gray-700/50 rounded-xl p-3">
                                    <i data-lucide="hard-drive" class="h-5 w-5 text-green-500 dark:text-green-400"></i>
                                    <div>
                                        <p class="text-xs text-gray-500 dark:text-gray-400 font-semibold" data-i18n="cardSize">${appManager.t('cardSize')}</p>
                                        <p class="text-sm font-bold text-gray-900 dark:text-white">${file.size}</p>
                                    </div>
                                </div>

                                <div class="flex items-center gap-3 bg-gray-50 dark:bg-gray-700/50 rounded-xl p-3">
                                    <i data-lucide="download" class="h-5 w-5 text-orange-500 dark:text-orange-400"></i>
                                    <div>
                                        <p class="text-xs text-gray-500 dark:text-gray-400 font-semibold" data-i18n="cardDownloads">${appManager.t('cardDownloads')}</p>
                                        <p class="text-sm font-bold text-gray-900 dark:text-white">${file.downloads || 0}</p>
                                    </div>
                                </div>
                            </div>

                            <div class="flex items-center gap-3 mb-6 p-3 bg-blue-50 dark:bg-blue-900/20 rounded-xl border border-blue-200 dark:border-blue-800">
                                <div class="h-10 w-10 rounded-full overflow-hidden flex-shrink-0 bg-indigo-100 dark:bg-indigo-800 flex items-center justify-center">
                                    ${(() => {
                                                                const uploader = users.find(u => String(u.email || '').toLowerCase() === String(file.uploadedBy || '').toLowerCase());
                                        if (uploader && uploader.avatar) {
                                            return `<img src="${uploader.avatar}" alt="uploader" class="h-full w-full object-cover">`;
                                        }
                                        const initials = (uploader && uploader.name) ? uploader.name.split(/\s+/).map(p=>p[0]).slice(0,2).join('').toUpperCase() : (file.uploadedByName ? file.uploadedByName.split(/\s+/).map(p=>p[0]).slice(0,2).join('').toUpperCase() : 'U');
                                        return `<span class="text-sm font-semibold text-white">${initials}</span>`;
                                    })()}
                                </div>
                                <div>
                                    <p class="text-xs text-blue-600 dark:text-blue-300 font-semibold" data-i18n="cardUploadedBy">${appManager.t('cardUploadedBy')}</p>
                                    <p class="text-sm font-bold text-blue-900 dark:text-blue-100">${file.uploadedByName || file.uploadedBy || appManager.t('unknown')}</p>
                                </div>
                            </div>

                            <div class="flex gap-3 pt-2">
                                <button onclick="downloadFile(${file.id})" class="flex-1 bg-gradient-to-r from-blue-600 to-blue-700 text-white px-4 py-3 rounded-xl hover:from-blue-700 hover:to-blue-800 transition-all duration-200 text-sm font-semibold flex items-center justify-center gap-2 shadow-md hover:shadow-lg" data-i18n="download">
                                    <i data-lucide="download" class="h-5 w-5"></i>
                                    <span>${appManager.t('download')}</span>
                                </button>
                                <button onclick="showFileDetails(${file.id})" class="flex-1 bg-gray-100 dark:bg-gray-700 text-gray-900 dark:text-white px-4 py-3 rounded-xl hover:bg-gray-200 dark:hover:bg-gray-600 transition-all duration-200 text-sm font-semibold flex items-center justify-center gap-2" data-i18n="viewMore">
                                    <i data-lucide="info" class="h-5 w-5"></i>
                                    <span>${appManager.t('viewMore')}</span>
                                </button>
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    });

    filesGrid.innerHTML = sectionsHTML;

    if (typeof lucide !== 'undefined') lucide.createIcons();
}

// دالة تحميل الملف
function downloadFile(fileId) {
    if (!auth.isAuthenticated()) {
        toast.error(appManager.t('mustLoginToDownload') || 'You must be logged in to download files');
        setTimeout(() => { window.location.href = 'login.html'; }, 900);
        return;
    }

    const files = JSON.parse(localStorage.getItem('files') || '[]');
    const fileIndex = files.findIndex(f => f.id === fileId);
    
    if (fileIndex === -1) {
        toast.error(appManager.t('fileNotFound') || 'File not found');
        return;
    }

    try {
        const request = indexedDB.open('summarizee', 1);
        
        request.onsuccess = () => {
            const db = request.result;
            const transaction = db.transaction('files', 'readonly');
            const store = transaction.objectStore('files');
            const getRequest = store.get(fileId);
            
            getRequest.onsuccess = () => {
                const result = getRequest.result;
                
                if (result && result.blob) {
                    if (!files[fileIndex].downloads) files[fileIndex].downloads = 0;
                    files[fileIndex].downloads += 1;
                    localStorage.setItem('files', JSON.stringify(files));
                    fetchFiles();

                    const downloadLink = document.createElement('a');
                    downloadLink.href = URL.createObjectURL(result.blob);
                    downloadLink.download = files[fileIndex].title || `file_${fileId}`;
                    document.body.appendChild(downloadLink);
                    downloadLink.click();
                    document.body.removeChild(downloadLink);
                    URL.revokeObjectURL(downloadLink.href);
                    
                    toast.success(appManager.t('downloadStarted') || 'Download started!');
                } else {
                    toast.warning(appManager.t('fileNotAvailable') || 'File data not available for download');
                }
            };
            
            getRequest.onerror = () => {
                toast.error(appManager.t('downloadError') || 'Error accessing file');
            };
        };
        
        request.onerror = () => {
            toast.error(appManager.t('downloadError') || 'Error accessing file storage');
        };
    } catch (err) {
        console.error('Download error:', err);
        toast.error(appManager.t('downloadError') || 'Error downloading file');
    }
}

// دالة عرض تفاصيل الملف
function showFileDetails(fileId) {
    const files = JSON.parse(localStorage.getItem('files') || '[]');
    const file = files.find(f => f.id === fileId);
    const users = JSON.parse(localStorage.getItem('users') || '[]');
    
    if (!file) {
        toast.error(appManager.t('fileNotFound') || 'الملف غير موجود');
        return;
    }

    const modal = document.createElement('div');
    modal.className = 'fixed inset-0 bg-black/50 dark:bg-black/70 flex items-center justify-center z-50 p-4';
    modal.onclick = (e) => e.target === modal && modal.remove();
    
    modal.innerHTML = `
        <div class="bg-white dark:bg-gray-800 rounded-2xl shadow-2xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
            <div class="sticky top-0 bg-gradient-to-r from-blue-600 to-blue-700 text-white p-6 flex justify-between items-start">
                <div>
                    <h2 class="text-2xl font-bold mb-2">${security.sanitizeHTML(file.title)}</h2>
                    <p class="text-blue-100">${security.sanitizeHTML(file.subject)}</p>
                </div>
                <button onclick="this.closest('.fixed').remove()" class="text-white hover:bg-blue-800 p-2 rounded-full transition">
                    <i data-lucide="x" class="h-6 w-6"></i>
                </button>
            </div>

            <div class="p-6 space-y-6">
                <div>
                    <span class="px-4 py-2 rounded-full bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300 font-semibold">
                        ${appManager.translateFileType ? appManager.translateFileType(file.type) : file.type}
                    </span>
                </div>

                ${file.description ? `
                <div>
                    <h3 class="text-lg font-bold text-gray-900 dark:text-white mb-2">${appManager.t('description')}</h3>
                    <p class="text-gray-700 dark:text-gray-300 leading-relaxed">${security.sanitizeHTML(file.description)}</p>
                </div>
                ` : ''}

                <div class="grid grid-cols-2 gap-4">
                    <div class="bg-amber-50 dark:bg-amber-900/20 p-4 rounded-lg border border-amber-200 dark:border-amber-800">
                        <div class="flex items-center gap-2 mb-2">
                            <i data-lucide="book-open" class="h-5 w-5 text-amber-600"></i>
                            <p class="text-sm text-amber-700 dark:text-amber-300 font-semibold">${appManager.t('pageCount') || 'عدد الصفحات'}</p>
                        </div>
                        <p class="text-2xl font-bold text-amber-900 dark:text-amber-100">${file.pageCount || 'N/A'}</p>
                    </div>

                    <div class="bg-green-50 dark:bg-green-900/20 p-4 rounded-lg border border-green-200 dark:border-green-800">
                        <div class="flex items-center gap-2 mb-2">
                            <i data-lucide="download" class="h-5 w-5 text-green-600"></i>
                            <p class="text-sm text-green-700 dark:text-green-300 font-semibold">${appManager.t('downloads') || 'التحميلات'}</p>
                        </div>
                        <p class="text-2xl font-bold text-green-900 dark:text-green-100">${file.downloads || 0}</p>
                    </div>

                    <div class="bg-purple-50 dark:bg-purple-900/20 p-4 rounded-lg border border-purple-200 dark:border-purple-800">
                        <div class="flex items-center gap-2 mb-2">
                            <i data-lucide="hard-drive" class="h-5 w-5 text-purple-600"></i>
                            <p class="text-sm text-purple-700 dark:text-purple-300 font-semibold">${appManager.t('size') || 'الحجم'}</p>
                        </div>
                        <p class="text-lg font-bold text-purple-900 dark:text-purple-100">${file.size}</p>
                    </div>

                    <div class="bg-red-50 dark:bg-red-900/20 p-4 rounded-lg border border-red-200 dark:border-red-800">
                        <div class="flex items-center gap-2 mb-2">
                            <i data-lucide="calendar" class="h-5 w-5 text-red-600"></i>
                            <p class="text-sm text-red-700 dark:text-red-300 font-semibold">${appManager.t('date') || 'التاريخ'}</p>
                        </div>
                        <p class="text-lg font-bold text-red-900 dark:text-red-100">${file.date}</p>
                    </div>
                </div>

                <div class="bg-indigo-50 dark:bg-indigo-900/20 p-4 rounded-lg border border-indigo-200 dark:border-indigo-800">
                    <div class="flex items-center gap-3">
                        <div class="h-12 w-12 rounded-full overflow-hidden flex-shrink-0 bg-indigo-100 dark:bg-indigo-800 flex items-center justify-center">
                            ${(() => {
                                const uploader = users.find(u => String(u.email || '').toLowerCase() === String(file.uploadedBy || '').toLowerCase());
                                if (uploader && uploader.avatar) {
                                    return `<img src="${uploader.avatar}" alt="uploader" class="h-full w-full object-cover">`;
                                }
                                const initials = (uploader && uploader.name) ? uploader.name.split(/\s+/).map(p=>p[0]).slice(0,2).join('').toUpperCase() : (file.uploadedByName ? file.uploadedByName.split(/\s+/).map(p=>p[0]).slice(0,2).join('').toUpperCase() : 'U');
                                return `<span class="text-sm font-semibold text-white">${initials}</span>`;
                            })()}
                        </div>
                        <div>
                            <p class="text-sm text-indigo-700 dark:text-indigo-300 font-semibold">${appManager.t('uploadedBy') || 'رفع بواسطة'}</p>
                            <p class="text-lg font-bold text-indigo-900 dark:text-indigo-100">${file.uploadedByName || file.uploadedBy || 'مجهول'}</p>
                        </div>
                    </div>
                </div>

                <!-- original author removed: profiles are used instead -->

                <div class="flex gap-3 pt-4 border-t border-gray-200 dark:border-gray-700">
                    <button onclick="downloadFile(${file.id}); this.closest('.fixed').remove();" class="flex-1 bg-blue-600 text-white px-4 py-3 rounded-lg hover:bg-blue-700 transition font-medium flex items-center justify-center gap-2">
                        <i data-lucide="download" class="h-5 w-5"></i>
                        ${appManager.t('download')}
                    </button>
                    <button onclick="this.closest('.fixed').remove()" class="flex-1 bg-gray-200 dark:bg-gray-700 text-gray-900 dark:text-white px-4 py-3 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600 transition font-medium flex items-center justify-center gap-2">
                        <i data-lucide="x" class="h-5 w-5"></i>
                        ${appManager.t('close')}
                    </button>
                </div>
            </div>
        </div>
    `;

    document.body.appendChild(modal);
    
    if (typeof lucide !== 'undefined') lucide.createIcons();
}
