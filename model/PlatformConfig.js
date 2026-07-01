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
    { name: 'MOMBASA CENTRE', lat: -4.0546356, lng: 39.6826, radiusMeters: 100, active: true },
    { name: 'SHIMONI CENTRE', lat: -4.0546356, lng: 39.6826, radiusMeters: 100, active: true },
    { name: 'KISUMU CENTRE', lat: -0.059149, lng: 34.8066, radiusMeters: 100, active: true },
    { name: 'KEGATI STATION', lat: -0.644496, lng: 34.7481, radiusMeters: 100, active: true },
    { name: 'TURKANA STATION', lat: 3.08222, lng: 36.0749, radiusMeters: 100, active: true },
    { name: 'NAIROBI STATION', lat: -1.24936, lng: 36.7968, radiusMeters: 100, active: true },
    { name: 'NAIVASHA STATION', lat: -0.664008, lng: 36.4651, radiusMeters: 100, active: true },
    { name: 'BARINGO STATION', lat: 0.604245, lng: 35.9773, radiusMeters: 100, active: true },
    { name: 'SANGORO STATION', lat: -0.394861, lng: 34.7374, radiusMeters: 100, active: true },
    { name: 'SAGANA CENTRE', lat: -0.669415, lng: 37.2061, radiusMeters: 100, active: true },
    { name: 'GAZI STATION', lat: -4.0546356, lng: 39.6826, radiusMeters: 100, active: true },
    { name: 'MUTONGA CENTER', lat: -4.0546356, lng: 39.6826, radiusMeters: 100, active: true },
];

const defaultDropdowns = {
    genders: ['Male', 'Female'],
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
        name: 'Midnight Current',
        primaryColor: '#031B2E',
        secondaryColor: '#0A3D62',
        accentColor: '#368DC5',
        surfaceColor: '#F3F8FC',
        textColor: '#0F172A',
    },
    {
        name: 'KMFRI Ocean',
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
    clockInMessage: 'Reminder: please clock in for your scheduled KMFRI workday.',
    clockOutMessage: 'Reminder: please clock out before leaving your duty station.',
    channels: ['in_app'],
};

const defaultGeofence = {
    radiusMeters: 100,
    enabled: false,
};

const defaultAttendancePolicy = {
    standardClockIn: '08:00',
    standardClockOut: '17:00',
    gracePeriodMinutes: 15,
    allowClockOutsideStation: false,
    requireBiometricVerification: true,
};

const defaultMasterSettings = {
    allowEmployeeSelfRegistration: false,
    maintenanceMode: false,
    requirePasswordResetOnFirstLogin: false,
    maxDevicesPerUser: 2,
};

const stationSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    lat: { type: Number, default: 0 },
    lng: { type: Number, default: 0 },
    radiusMeters: { type: Number, default: 100 },
    active: { type: Boolean, default: true },
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
        channels: { type: [String], default: defaultNotificationReminders.channels },
    },
    geofence: {
        radiusMeters: { type: Number, default: defaultGeofence.radiusMeters },
        enabled: { type: Boolean, default: defaultGeofence.enabled },
    },
    attendancePolicy: {
        standardClockIn: { type: String, default: defaultAttendancePolicy.standardClockIn },
        standardClockOut: { type: String, default: defaultAttendancePolicy.standardClockOut },
        gracePeriodMinutes: { type: Number, default: defaultAttendancePolicy.gracePeriodMinutes },
        allowClockOutsideStation: { type: Boolean, default: defaultAttendancePolicy.allowClockOutsideStation },
        requireBiometricVerification: { type: Boolean, default: defaultAttendancePolicy.requireBiometricVerification },
    },
    departments: { type: [String], default: defaultDepartments },
    stations: { type: [stationSchema], default: defaultStations },
    dropdowns: {
        type: Map,
        of: [String],
        default: defaultDropdowns,
    },
    masterSettings: {
        allowEmployeeSelfRegistration: { type: Boolean, default: defaultMasterSettings.allowEmployeeSelfRegistration },
        maintenanceMode: { type: Boolean, default: defaultMasterSettings.maintenanceMode },
        requirePasswordResetOnFirstLogin: { type: Boolean, default: defaultMasterSettings.requirePasswordResetOnFirstLogin },
        maxDevicesPerUser: { type: Number, default: defaultMasterSettings.maxDevicesPerUser },
    },
}, { timestamps: true });

const normalizeStation = (station) => {
    if (typeof station === 'string') {
        return { name: station, lat: 0, lng: 0, radiusMeters: 100, active: true };
    }
    return {
        name: station?.name || '',
        lat: Number(station?.lat ?? 0),
        lng: Number(station?.lng ?? 0),
        radiusMeters: Number(station?.radiusMeters ?? 100),
        active: station?.active !== false,
    };
};

export const getDefaultPlatformConfig = () => ({
    logoUrl: '',
    branding: { ...defaultBranding },
    activeThemeName: 'KMFRI Ocean',
    themes: defaultThemes.map((theme) => ({ ...theme })),
    notificationReminders: { ...defaultNotificationReminders, channels: [...defaultNotificationReminders.channels] },
    geofence: { ...defaultGeofence },
    attendancePolicy: { ...defaultAttendancePolicy },
    departments: [...defaultDepartments],
    stations: defaultStations.map((station) => ({ ...station })),
    dropdowns: { ...defaultDropdowns },
    masterSettings: { ...defaultMasterSettings },
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
        if (!Array.isArray(cfg.themes) || cfg.themes.length === 0) {
            cfg.themes = defaultThemes;
            changed = true;
        }
        if (!cfg.activeThemeName) {
            cfg.activeThemeName = defaultThemes[0].name;
            changed = true;
        }
        if (changed) await cfg.save();
    }
    return cfg;
};

export default mongoose.model('PlatformConfig', platformConfigSchema);
