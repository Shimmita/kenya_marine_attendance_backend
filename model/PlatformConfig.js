import mongoose from 'mongoose';

const defaultDepartments = [
    "Oceans and Coastal Systems & Blue Economy Research",
    "Marine and Coastal Fisheries Research",
    "Oceanography and Hydrography Research",
    "Freshwater Systems Research",
    "Freshwater Fisheries Research",
    "Limnology Research",
    "Aquaculture Research",
    "Freshwater Aquaculture Research",
    "Mariculture Research",
    "Socioeconomic Assessment and Monitoring",
    "Economic Valuation and Marketing",
    "Economic Analysis and Community Development",
    "Laboratory Services",
    "Maritime Services",
    "Finance and Accounting",
    "Human Resource Management and Administration",
    "Information Science",
    "Engineering and Maintenance",
    "Corporate Communication and Public Relations",
    "Strategy and Planning",
    "Performance Management, Monitoring and Evaluation",
    "Information Communication Technology (ICT)",
    "Partnership Development and Resource Mobilization",
    "Technical Capacity Building",
    "Quality Assurance and Compliance",
    "Business Development",
    "Corporation Secretary and Legal Services",
    "Internal Audit",
    "Supply Chain Management",
];

const defaultStations = [
    { name: 'MOMBASA CENTRE', lat: -4.0546356, lng: 39.6826, radiusMeters: 500, active: true },
    { name: 'SHIMONI CENTRE', lat: -4.644, lng: 39.375, radiusMeters: 500, active: true },
    { name: 'KISUMU CENTRE', lat: -0.059149, lng: 34.8066, radiusMeters: 500, active: true },
    { name: 'KEGATI STATION', lat: -0.644496, lng: 34.7481, radiusMeters: 500, active: true },
    { name: 'TURKANA STATION', lat: 3.08222, lng: 36.0749, radiusMeters: 500, active: true },
    { name: 'NAIROBI STATION', lat: -1.24936, lng: 36.7968, radiusMeters: 500, active: true },
    { name: 'NAIVASHA STATION', lat: -0.664008, lng: 36.4651, radiusMeters: 500, active: true },
    { name: 'BARINGO STATION', lat: 0.604245, lng: 35.9773, radiusMeters: 500, active: true },
    { name: 'SANGORO STATION', lat: -0.394861, lng: 34.7374, radiusMeters: 500, active: true },
    { name: 'SAGANA CENTRE', lat: -0.669415, lng: 37.2061, radiusMeters: 500, active: true },
    { name: 'GAZI STATION', lat: -4.0546356, lng: 39.6826, radiusMeters: 500, active: true },
    { name: 'MUTONGA CENTER', lat: -4.0546356, lng: 39.6826, radiusMeters: 500, active: true },
];

const defaultDropdowns = {
    leaveTypes: ['Adoption Leave', 'Annual Leave', 'Compassionate Leave', 'Paternity Leave', 'Sick Leave', 'Study Leave', 'Terminal Leave'],
    absenceReasons: ['Sickness', 'Fieldwork', 'Workshop', 'Official Assignment', 'Emergency', 'Other'],
    roles: ['employee', 'intern', 'attachee'],
    ranks: ['admin', 'hr', 'supervisor', 'ceo', 'user', 'auditor', 'superadmin'],
};

const defaultBranding = {
    organizationName: 'Kenya Marine and Fisheries Research Institute',
    shortName: 'KMFRI',
    primaryColor: '#0A3D62',
    secondaryColor: '#005B96',
    accentColor: '#48C9B0',
    supportEmail: '',
    supportPhone: '',
};

const defaultThemes = [
    {
        name: 'KMFRI Ocean',
        primaryColor: '#031B2E',
        secondaryColor: '#0A3D62',
        accentColor: '#368DC5',
        surfaceColor: '#F3F8FC',
        textColor: '#0F172A',
    },
    {
        name: 'Midnight Current',
        primaryColor: '#0A3D62',
        secondaryColor: '#005B96',
        accentColor: '#48C9B0',
        surfaceColor: '#F8FAFD',
        textColor: '#0F172A',
    },
    {
        name: 'Atlantic Deep',
        primaryColor: '#031B34',
        secondaryColor: '#0A3D62',
        accentColor: '#00E5FF',
        surfaceColor: '#F5FAFD',
        textColor: '#102A43',
    },
    {
        name: 'Blue Horizon',
        primaryColor: '#005B96',
        secondaryColor: '#368DC5',
        accentColor: '#87CEEB',
        surfaceColor: '#F8FCFF',
        textColor: '#153A52',
    },
    {
        name: 'Aqua Marine',
        primaryColor: '#0A3D62',
        secondaryColor: '#1A237E',
        accentColor: '#00E5FF',
        surfaceColor: '#F4FAFD',
        textColor: '#1F2937',
    },

    {
        name: 'Deep Ocean',
        primaryColor: '#051C30',
        secondaryColor: '#0A3D62',
        accentColor: '#00E5FF',
        surfaceColor: '#F5FAFC',
        textColor: '#0B1E2D',
    },

    {
        name: 'Marine Blue',
        primaryColor: '#1A237E',
        secondaryColor: '#005B96',
        accentColor: '#368DC5',
        surfaceColor: '#F4F8FC',
        textColor: '#172554',
    },

    {
        name: 'Coastal Blue',
        primaryColor: '#063970',
        secondaryColor: '#087CA7',
        accentColor: '#14B8A6',
        surfaceColor: '#EEF7FB',
        textColor: '#082F49',
    },

    {
        name: 'Ocean Breeze',
        primaryColor: '#005B96',
        secondaryColor: '#368DC5',
        accentColor: '#87CEEB',
        surfaceColor: '#F6FBFF',
        textColor: '#103B52',
    },

    {
        name: 'Aqua Horizon',
        primaryColor: '#0A3D62',
        secondaryColor: '#368DC5',
        accentColor: '#00E5FF',
        surfaceColor: '#F8FCFF',
        textColor: '#123047',
    },

    {
        name: 'Blue Lagoon',
        primaryColor: '#005B96',
        secondaryColor: '#1A237E',
        accentColor: '#48C9B0',
        surfaceColor: '#F2F8FC',
        textColor: '#1B365D',
    },

    {
        name: 'Sky Marine',
        primaryColor: '#368DC5',
        secondaryColor: '#0A3D62',
        accentColor: '#87CEEB',
        surfaceColor: '#F7FBFD',
        textColor: '#153A52',
    },

    {
        name: 'Arctic Blue',
        primaryColor: '#1565C0',
        secondaryColor: '#0A3D62',
        accentColor: '#00BCD4',
        surfaceColor: '#F5FAFF',
        textColor: '#0D2A45',
    },

    {
        name: 'Azure Research',
        primaryColor: '#0A3D62',
        secondaryColor: '#1976D2',
        accentColor: '#00ACC1',
        surfaceColor: '#F8FCFF',
        textColor: '#102A43',
    },

    {
        name: 'Sea Glass',
        primaryColor: '#005B96',
        secondaryColor: '#48C9B0',
        accentColor: '#00E5FF',
        surfaceColor: '#F7FCFB',
        textColor: '#1F2937',
    },


];

const defaultNotificationReminders = {
    clockInReminderMinutes: 15,
    clockOutReminderMinutes: 15,
    clockInMessage: 'Dear {firstName}, you did not clock in today. Please remember to clock in and out for your scheduled workday.',

    clockOutMessage: 'Dear {firstName}, please remember to clock out before leaving your station.',

    clockInSuccessMessage: 'Dear {firstName}, you have successfully checked in at {station} on {date} at {time} EAT.',

    clockOutSuccessMessage: 'Dear {firstName}, you have successfully checked out from {station} on {date} at {time} EAT.',

    internRegMessage: `Dear {firstName}, your KMFRI Attendance account is ready. Login: {email} | Password: {password}. Please change your password after login.`,

    staffRegMessage: `Dear {firstName}, your KMFRI Attendance account is ready. Login: {employeeId} | Password: {password}. Please change your password after login.`,

    authorisedClockOut: 'Dear {firstName}, you are authorised to clock out outside your assigned station.',

    clockOutsideGrantedMessage: 'Dear {firstName}, permission to clock outside "{station}" is granted from {startDate} to {endDate}. Reason: {reason}.',

    clockOutsideRevokedMessage: 'Dear {firstName}, permission to clock outside "{station}" has been revoked. Please follow standard clocking procedures.',

    accountActivatedMessage: 'Dear {firstName}, your KMFRI Attendance account has been activated. You may now access attendance services.',

    accountDeactivatedMessage: 'Dear {firstName}, your KMFRI Attendance account has been deactivated. Please contact HR for assistance.',

    accountExpiredMessage: 'Dear {firstName}, your KMFRI Attendance {role} account reached its end date ({endDate}) and has been automatically deactivated. Please contact HR for assistance.',

    maintenanceModeMessage: 'Dear {firstName}, KMFRI Attendance will be under scheduled maintenance from {startDate} to {endDate}. Services may be temporarily unavailable. Thank you for your patience.',

    maintenanceRestoredMessage: 'Dear {firstName}, KMFRI Attendance services have been restored. You may now continue using the platform.',

    holidayNoticeMessage: 'Dear {firstName}, today ({holidayDate}) is {holidayName}. KMFRI Attendance clocking is not required for the holiday. Normal clocking resumes on the next configured working day.',

    leaveSubmittedMessage: 'Dear {firstName}, your {type} request ({startDate}–{endDate}) has been submitted for review.',

    leaveApprovedMessage: 'Dear {firstName}, your {type} request ({startDate}–{endDate}) has been approved.',

    leaveRejectedMessage: 'Dear {firstName}, your {type} request ({startDate}–{endDate}) was rejected. Please contact your supervisor or HR.',

    leaveCancelledMessage: 'Dear {firstName}, your {type} request ({startDate}–{endDate}) has been cancelled.',

    manualLeaveEnabledMessage: 'Dear {firstName}, your attendance profile has been marked as on leave.',

    manualLeaveDisabledMessage: 'Dear {firstName}, your attendance profile has been removed from on-leave status.',

    missedClockOutMessage: 'Dear {firstName}, you did not clock out yesterday. Please ensure you complete your attendance records.',

    absentMessage: 'Dear {firstName}, no attendance was recorded for you yesterday. Please contact HR if this is incorrect.',

    channels: ["sms", "in_app"]
};


const defaultGeofence = {
    radiusMeters: 500,
    enabled: false,
};

const defaultAttendancePolicy = {

    standardClockIn: "08:00",

    standardClockOut: "17:00",

    gracePeriodMinutes: 15,

    minimumWorkHours: 8,

    halfDayWorkHours: 4,

    earlyDepartureGraceMinutes: 15,

    clockInReminderOffsetMinutes: 0,

    clockOutReminderOffsetMinutes: 0,

    midnightProcessingTime: "00:00",

    workingDays: [1, 2, 3, 4, 5],

    requireLocationForClocking: true,

    requireStationSelection: true,

    autoClockOutMissedSessions: true,

    markAbsenteesAutomatically: true,

    allowClockOutsideStation: true,

    requireBiometricVerification: true

};

const defaultClockingPoint = {
    otpLength: 4,
    otpExpirySeconds: 30,
    otpMaxAttempts: 3,
    otpResendSeconds: 30,
    otpMaxResends: 2,
};

const defaultMasterSettings = {
    maintenanceMode: false,
    maintenanceStartAt: null,
    maintenanceEndAt: null,
    maintenanceMessage: '',
    maintenanceNotifiedAt: null,
    maintenanceRestoredNotifiedAt: null,
    requirePasswordResetOnFirstLogin: true,
    maxDevicesPerUser: 2,
    biometricVerificationWindowMinutes: 5,
    sessionTimeoutMinutes: 20,
    enableAuditLogging: true,

};

const stationSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    lat: { type: Number, default: 0 },
    lng: { type: Number, default: 0 },
    radiusMeters: { type: Number, default: 500 },
    active: { type: Boolean, default: true },
    allowClockingPoint: { type: Boolean, default: false },
}, { _id: false });

const themeSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    primaryColor: { type: String, default: '#0A3D62' },
    secondaryColor: { type: String, default: '#005B96' },
    accentColor: { type: String, default: '#48C9B0' },
    surfaceColor: { type: String, default: '#f8fafd' },
    textColor: { type: String, default: '#0f172a' },
}, { _id: false });

const platformConfigSchema = new mongoose.Schema({
    logoUrl: { type: String, default: '' },
    branding: {
        organizationName: { type: String, default: defaultBranding.organizationName },
        shortName: { type: String, default: defaultBranding.shortName },
        primaryColor: { type: String, default: defaultBranding.primaryColor },
        secondaryColor: { type: String, default: defaultBranding.secondaryColor },
        accentColor: { type: String, default: defaultBranding.accentColor },
        supportEmail: { type: String, default: defaultBranding.supportEmail },
        supportPhone: { type: String, default: defaultBranding.supportPhone },
    },
    activeThemeName: { type: String, default: 'Midnight Current' },
    themes: { type: [themeSchema], default: defaultThemes },
    notificationReminders: {
        clockInReminderMinutes: { type: Number, default: defaultNotificationReminders.clockInReminderMinutes },
        clockOutReminderMinutes: { type: Number, default: defaultNotificationReminders.clockOutReminderMinutes },
        clockInMessage: { type: String, default: defaultNotificationReminders.clockInMessage },
        clockOutMessage: { type: String, default: defaultNotificationReminders.clockOutMessage },
        clockInSuccessMessage: { type: String, default: defaultNotificationReminders.clockInSuccessMessage },
        clockOutSuccessMessage: { type: String, default: defaultNotificationReminders.clockOutSuccessMessage },
        internRegMessage: { type: String, default: defaultNotificationReminders.internRegMessage },
        staffRegMessage: { type: String, default: defaultNotificationReminders.staffRegMessage },
        authorisedClockOut: { type: String, default: defaultNotificationReminders.authorisedClockOut },
        clockOutsideGrantedMessage: { type: String, default: defaultNotificationReminders.clockOutsideGrantedMessage },
        clockOutsideRevokedMessage: { type: String, default: defaultNotificationReminders.clockOutsideRevokedMessage },
        accountActivatedMessage: { type: String, default: defaultNotificationReminders.accountActivatedMessage },
        accountDeactivatedMessage: { type: String, default: defaultNotificationReminders.accountDeactivatedMessage },
        accountExpiredMessage: { type: String, default: defaultNotificationReminders.accountExpiredMessage },
        maintenanceModeMessage: { type: String, default: defaultNotificationReminders.maintenanceModeMessage },
        maintenanceRestoredMessage: { type: String, default: defaultNotificationReminders.maintenanceRestoredMessage },
        holidayNoticeMessage: { type: String, default: defaultNotificationReminders.holidayNoticeMessage },
        leaveSubmittedMessage: { type: String, default: defaultNotificationReminders.leaveSubmittedMessage },
        leaveApprovedMessage: { type: String, default: defaultNotificationReminders.leaveApprovedMessage },
        leaveRejectedMessage: { type: String, default: defaultNotificationReminders.leaveRejectedMessage },
        leaveCancelledMessage: { type: String, default: defaultNotificationReminders.leaveCancelledMessage },
        manualLeaveEnabledMessage: { type: String, default: defaultNotificationReminders.manualLeaveEnabledMessage },
        manualLeaveDisabledMessage: { type: String, default: defaultNotificationReminders.manualLeaveDisabledMessage },
        missedClockOutMessage: { type: String, default: defaultNotificationReminders.missedClockOutMessage },
        absentMessage: { type: String, default: defaultNotificationReminders.absentMessage },
        channels: { type: [String], default: defaultNotificationReminders.channels },
    },
    geofence: {
        radiusMeters: { type: Number, default: defaultGeofence.radiusMeters },
        enabled: { type: Boolean, default: defaultGeofence.enabled },
    },
    attendancePolicy: {

        standardClockIn: {
            type: String,
            default: defaultAttendancePolicy.standardClockIn
        },

        standardClockOut: {
            type: String,
            default: defaultAttendancePolicy.standardClockOut
        },

        gracePeriodMinutes: {
            type: Number,
            default: defaultAttendancePolicy.gracePeriodMinutes
        },

        minimumWorkHours: {
            type: Number,
            default: defaultAttendancePolicy.minimumWorkHours
        },

        halfDayWorkHours: {
            type: Number,
            default: defaultAttendancePolicy.halfDayWorkHours
        },

        earlyDepartureGraceMinutes: {
            type: Number,
            default: defaultAttendancePolicy.earlyDepartureGraceMinutes
        },

        clockInReminderOffsetMinutes: {
            type: Number,
            default: defaultAttendancePolicy.clockInReminderOffsetMinutes
        },

        clockOutReminderOffsetMinutes: {
            type: Number,
            default: defaultAttendancePolicy.clockOutReminderOffsetMinutes
        },

        midnightProcessingTime: {
            type: String,
            default: "00:00"
        },

        workingDays: {
            type: [Number],
            default: [1, 2, 3, 4, 5]
        },

        requireLocationForClocking: {
            type: Boolean,
            default: defaultAttendancePolicy.requireLocationForClocking
        },

        requireStationSelection: {
            type: Boolean,
            default: defaultAttendancePolicy.requireStationSelection
        },

        autoClockOutMissedSessions: {
            type: Boolean,
            default: defaultAttendancePolicy.autoClockOutMissedSessions
        },

        markAbsenteesAutomatically: {
            type: Boolean,
            default: defaultAttendancePolicy.markAbsenteesAutomatically
        },

        allowClockOutsideStation: {
            type: Boolean,
            default: defaultAttendancePolicy.allowClockOutsideStation
        },

        requireBiometricVerification: {
            type: Boolean,
            default: defaultAttendancePolicy.requireBiometricVerification
        }

    },
    clockingPoint: {
        otpLength: { type: Number, default: defaultClockingPoint.otpLength },
        otpExpirySeconds: { type: Number, default: defaultClockingPoint.otpExpirySeconds },
        otpMaxAttempts: { type: Number, default: defaultClockingPoint.otpMaxAttempts },
        otpResendSeconds: { type: Number, default: defaultClockingPoint.otpResendSeconds },
        otpMaxResends: { type: Number, default: defaultClockingPoint.otpMaxResends },
    },
    departments: { type: [String], default: defaultDepartments },
    stations: { type: [stationSchema], default: defaultStations },
    dropdowns: {
        type: Map,
        of: [String],
        default: defaultDropdowns,
    },
    masterSettings: {
        maintenanceMode: { type: Boolean, default: defaultMasterSettings.maintenanceMode },
        maintenanceStartAt: { type: Date, default: defaultMasterSettings.maintenanceStartAt },
        maintenanceEndAt: { type: Date, default: defaultMasterSettings.maintenanceEndAt },
        maintenanceMessage: { type: String, default: defaultMasterSettings.maintenanceMessage },
        maintenanceNotifiedAt: { type: Date, default: defaultMasterSettings.maintenanceNotifiedAt },
        maintenanceRestoredNotifiedAt: { type: Date, default: defaultMasterSettings.maintenanceRestoredNotifiedAt },
        requirePasswordResetOnFirstLogin: { type: Boolean, default: defaultMasterSettings.requirePasswordResetOnFirstLogin },
        maxDevicesPerUser: { type: Number, default: defaultMasterSettings.maxDevicesPerUser },
        biometricVerificationWindowMinutes: { type: Number, default: defaultMasterSettings.biometricVerificationWindowMinutes },
        sessionTimeoutMinutes: { type: Number, default: defaultMasterSettings.sessionTimeoutMinutes },
        enableAuditLogging: { type: Boolean, default: defaultMasterSettings.enableAuditLogging },
    },
}, { timestamps: true });


// holidays schema 
const holidaySchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },

    date: {
        type: Date,
        required: true
    },

    recurring: {
        type: Boolean,
        default: false
    },

    active: {
        type: Boolean,
        default: true
    },

    description: {
        type: String,
        default: ""
    }

}, { _id: true });


const normalizeStation = (station) => {
    if (typeof station === 'string') {
        return { name: station, lat: 0, lng: 0, radiusMeters: 500, active: true, allowClockingPoint: false };
    }
    return {
        name: station?.name || '',
        lat: Number(station?.lat ?? 0),
        lng: Number(station?.lng ?? 0),
        radiusMeters: Number(station?.radiusMeters ?? 500),
        active: station?.active !== false,
        allowClockingPoint: station?.allowClockingPoint === true,
    };
};

const applyNestedDefaults = (target, defaults) => {
    let changed = false;

    for (const [key, value] of Object.entries(defaults)) {
        if (typeof target?.[key] === 'undefined') {
            target[key] = Array.isArray(value) ? [...value] : value;
            changed = true;
        }
    }

    return changed;
};

export const getDefaultPlatformConfig = () => ({
    logoUrl: '',
    branding: { ...defaultBranding },
    activeThemeName: 'KMFRI Ocean',
    themes: defaultThemes.map((theme) => ({ ...theme })),
    notificationReminders: { ...defaultNotificationReminders, channels: [...defaultNotificationReminders.channels] },
    geofence: { ...defaultGeofence },
    attendancePolicy: { ...defaultAttendancePolicy },
    clockingPoint: { ...defaultClockingPoint },
    departments: [...defaultDepartments],
    stations: defaultStations.map((station) => ({ ...station })),
    dropdowns: { ...defaultDropdowns },
    masterSettings: { ...defaultMasterSettings },
    holidays: defaultHolidays.map((holiday) => ({ ...holiday })),
});



const defaultHolidays = [
    {
        name: "New Year's Day",
        date: new Date("2026-01-01"),
        recurring: true,
        active: true
    },
    {
        name: "Good Friday",
        date: new Date("2026-04-03"),
        recurring: false,
        active: true,
        description: "Movable Kenya public holiday. Review yearly against the official gazette."
    },
    {
        name: "Easter Monday",
        date: new Date("2026-04-06"),
        recurring: false,
        active: true,
        description: "Movable Kenya public holiday. Review yearly against the official gazette."
    },
    {
        name: "Idd-ul-Fitr",
        date: new Date("2026-03-20"),
        recurring: false,
        active: true,
        description: "Movable Kenya public holiday. Review yearly against the official gazette."
    },
    {
        name: "Labour Day",
        date: new Date("2026-05-01"),
        recurring: true,
        active: true
    },
    {
        name: "Madaraka Day",
        date: new Date("2026-06-01"),
        recurring: true,
        active: true
    },
    {
        name: "Idd-ul-Adha",
        date: new Date("2026-05-27"),
        recurring: false,
        active: true,
        description: "Movable Kenya public holiday. Review yearly against the official gazette."
    },
    {
        name: "Mazingira Day",
        date: new Date("2026-10-10"),
        recurring: true,
        active: true
    },
    {
        name: "Mashujaa Day",
        date: new Date("2026-10-20"),
        recurring: true,
        active: true
    },
    {
        name: "Jamhuri Day",
        date: new Date("2026-12-12"),
        recurring: true,
        active: true
    },
    {
        name: "Christmas Day",
        date: new Date("2026-12-25"),
        recurring: true,
        active: true
    },
    {
        name: "Boxing Day",
        date: new Date("2026-12-26"),
        recurring: true,
        active: true
    }
];


platformConfigSchema.add({

    holidays: {

        type: [holidaySchema],

        default: defaultHolidays

    }

});

// We only ever expect a single document. Helper static to fetch or create default.
platformConfigSchema.statics.getSingleton = async function () {
    let cfg = await this.findOne();
    if (!cfg) {
        cfg = await this.create({});
    } else {
        let changed = false;
        const needsDepartments = !Array.isArray(cfg.departments) || cfg.departments.length === 0;
        const needsStations = !Array.isArray(cfg.stations) || cfg.stations.length === 0;
        if (needsDepartments) {
            cfg.departments = defaultDepartments;
            changed = true;
        }
        if (needsStations) {
            cfg.stations = defaultStations;
            changed = true;
        }
        cfg.stations = cfg.stations.map(normalizeStation).filter((station) => station.name);
        if (!cfg.dropdowns || cfg.dropdowns.size === 0) {
            cfg.dropdowns = defaultDropdowns;
            changed = true;
        }
        if (!cfg.attendancePolicy) {
            cfg.attendancePolicy = { ...defaultAttendancePolicy };
            changed = true;
        }
        if (!cfg.clockingPoint) {
            cfg.clockingPoint = { ...defaultClockingPoint };
            changed = true;
        }
        if (!cfg.masterSettings) {
            cfg.masterSettings = { ...defaultMasterSettings };
            changed = true;
        }
        if (!Array.isArray(cfg.themes) || cfg.themes.length === 0) {
            cfg.themes = defaultThemes;
            changed = true;
        }
        if (!Array.isArray(cfg.holidays) || cfg.holidays.length === 0) {
            cfg.holidays = defaultHolidays;
            cfg.markModified('holidays');
            changed = true;
        }
        for (const [key, value] of Object.entries(defaultNotificationReminders)) {
            if (typeof cfg.notificationReminders?.[key] === 'undefined') {
                cfg.notificationReminders[key] = value;
                changed = true;
            }
        }
        if (applyNestedDefaults(cfg.attendancePolicy, defaultAttendancePolicy)) {
            cfg.markModified('attendancePolicy');
            changed = true;
        }
        if (applyNestedDefaults(cfg.clockingPoint, defaultClockingPoint)) {
            cfg.markModified('clockingPoint');
            changed = true;
        }
        if (applyNestedDefaults(cfg.masterSettings, defaultMasterSettings)) {
            cfg.markModified('masterSettings');
            changed = true;
        }
        if (Number(cfg.masterSettings?.sessionTimeoutMinutes) === 1440) {
            cfg.masterSettings.sessionTimeoutMinutes = defaultMasterSettings.sessionTimeoutMinutes;
            cfg.markModified('masterSettings');
            changed = true;
        }
        ['allowEmployeeSelfRegistration', 'enableAttendanceExports', 'enableLeaveManagement', 'enableSupervisorManagement'].forEach((key) => {
            if (typeof cfg.masterSettings?.[key] !== 'undefined') {
                cfg.masterSettings[key] = undefined;
                cfg.markModified('masterSettings');
                changed = true;
            }
        });
        if (!cfg.activeThemeName) {
            cfg.activeThemeName = defaultThemes[0].name;
            changed = true;
        }
        if (changed) await cfg.save();
    }
    return cfg;
};

export default mongoose.model('PlatformConfig', platformConfigSchema);
