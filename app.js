const express = require('express');
const mysql = require('mysql2');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: false }));

// School and Diploma Data
const schoolDiplomas = {
    SOI: [
        'Diploma in Enterprise Cloud Computing & Management',
        'Diploma in Applied AI & Analytics',
        'Diploma in Financial Technology',
        'Diploma in Information Technology',
        'Diploma in Cybersecurity & Digital Forensics'
    ],
    SAS: [
        'Diploma in Biomedical Science',
        'Diploma in Biological Sciences',
        'Diploma in Applied Chemistry',
        'Diploma in Pharmaceutical Science',
        'Diploma in Environmental & Marine Science'
    ],
    SEG: [
        'Diploma in Aerospace Engineering',
        'Diploma in Aviation Management',
        'Diploma in Business Process & Engineering Management',
        'Diploma in Electrical & Electronic Engineering',
        'Diploma in Engineering',
        'Diploma in Mobility & Robotic Systems',
        'Diploma in Supply Chain Management',
        'Diploma in Sustainable Built Environment'
    ],
    SOH: [
        'Diploma in Events & Project Management',
        'Diploma in Hotel & Leisure Management',
        'Diploma in Restaurant & Culinary Management',
        'Diploma in Hospitality & Tourism Management'
    ],
    SSH: [
        'Diploma in Integrated Community Care',
        'Diploma in Outdoor Education',
        'Diploma in Sport Coaching',
        'Diploma in Sport & Exercise Science',
        'Diploma in Sports & Health'
    ],
    STA: [
        'Diploma in Arts & Entertainment Production Management',
        'Diploma in Design',
        'Diploma in Digital Content Creation',
        'Diploma in Sonic Arts'
    ],
    SBZ: [
        'Diploma in Business',
        'Diploma in Consumer Insights & Psychology',
        'Diploma in Human Resource Management with Psychology',
        'Diploma in Mass Communication'
    ]
};

const schoolNames = {
    SOI: 'School of Infocomm',
    SAS: 'School of Applied Science',
    SEG: 'School of Engineering',
    SOH: 'School of Hospitality',
    SSH: 'School of Sports and Health',
    STA: 'School of Technology for Arts, Media and Design',
    SBZ: 'School of Business'
};

// Internship Categories
const internshipCategories = [
    'Software Development', 'Cybersecurity', 'Cloud', 'Networking',
    'Data Analytics', 'AI', 'Healthcare', 'Engineering', 'Business', 'Design'
];

// Database Connection
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: process.env.DB_PASSWORD || 'RP738964$',
    database: 'c237_team5_internshipportal'
});

connection.connect((error) => {
    if (error) {
        console.error('MySQL connection error:', error.message);
        return;
    }
    console.log('MySQL Database Connected!');
});



// ==========================================
// Done By: ZIN WITYEE AUNG 25040225
// Feature: Session Management
// Kept in shared setup because all routes use req.session.
// ==========================================
app.use(session({
    secret: 'c237-internship-portal-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 1000 * 60 * 60 * 24 * 7
    }
}));

app.locals.user = null;
app.locals.schoolDiplomas = schoolDiplomas;
app.locals.schoolNames = schoolNames;
app.locals.internshipCategories = internshipCategories;

// School and Diploma Validation
function isValidSchoolAndDiploma(school, diploma) {
    return schoolDiplomas[school] && schoolDiplomas[school].includes(diploma);
}

// =====================================================
// Done By: ZIN WITYEE AUNG 25040225
// ZOEY
// User Registration, Login, Session Management
// and Role-Based Access Control
// =====================================================
// Session middleware is kept in shared setup because routes depend on req.session.
function checkAuthenticated(req, res, next) {
    if (!req.session.user) {
        return res.redirect('/login?error=Please+log+in+to+continue.');
    }
    res.locals.user = req.session.user;
    next();
}

function checkStudent(req, res, next) {
    if (req.session.user.role !== 'student') {
        return res.status(403).render('error', {
            message: 'Only students can access this page.'
        });
    }
    next();
}

function checkAdmin(req, res, next) {
    if (req.session.user.role !== 'admin') {
        return res.status(403).render('error', {
            message: 'Only admins can access this page.'
        });
    }
    next();
}

// Zoey - Registration, login and logout routes
app.get('/register', (req, res) => {
    if (req.session.user) {
        return res.redirect('/internships');
    }
    res.render('register', { error: null, formData: {} });
});

app.post('/register', (req, res) => {
    const { username, email, password, confirmPassword, school, diploma } = req.body;
    const formData = { username, email, school, diploma };

    if (!username || !email || !password || !confirmPassword || !school || !diploma) {
        return res.render('register', { error: 'All fields are required.', formData });
    }
    if (!isValidSchoolAndDiploma(school, diploma)) {
        return res.render('register', {
            error: 'Please select a valid school and diploma.',
            formData
        });
    }
    if (password.length < 6) {
        return res.render('register', {
            error: 'Password must be at least 6 characters long.',
            formData
        });
    }
    if (password !== confirmPassword) {
        return res.render('register', { error: 'Passwords do not match.', formData });
    }

    const sql = `INSERT INTO users (name, email, password, role, school, diploma)
                 VALUES (?, ?, SHA2(?, 256), ?, ?, ?)`;
    connection.query(sql, [username, email, password, 'student', school, diploma], (error) => {
        if (error) {
            if (error.code === 'ER_DUP_ENTRY') {
                return res.render('register', {
                    error: 'An account with this email already exists.',
                    formData
                });
            }
            console.error('Registration error:', error.message);
            return res.send('Error registering user');
        }
        res.redirect('/login?message=Registration+successful.+Please+log+in.');
    });
});

app.get('/login', (req, res) => {
    if (req.session.user) {
        return res.redirect('/internships');
    }
    res.render('login', {
        error: req.query.error || null,
        message: req.query.message || null
    });
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.render('login', { error: 'All fields are required.', message: null });
    }

    const sql = `SELECT userId, name AS username, email, role, school, diploma
                 FROM users
                 WHERE email = ? AND password = SHA2(?, 256)`;
    connection.query(sql, [email, password], (error, results) => {
        if (error) {
            console.error('Login error:', error.message);
            return res.send('Error logging in');
        }
        if (results.length === 0) {
            return res.render('login', {
                error: 'Invalid email or password.',
                message: null
            });
        }

        req.session.user = results[0];
        res.redirect('/internships');
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/login?message=You+have+logged+out.');
    });
});

// =====================================================
// Done By: ZELIA TAN LING RUI 25046792
// ZELIA
// Internship Viewing, Adding, Editing and Deleting
// =====================================================
app.get('/internships', checkAuthenticated, (req, res) => {
    const search = (req.query.search || '').trim();
    const school = req.session.user.role === 'student'
        ? req.session.user.school
        : (req.query.school || '');
    const diploma = req.query.diploma || '';
    const category = req.query.category || '';
    let sql = `SELECT i.internshipId, i.companyName, i.jobTitle, i.location, i.allowance,
               i.school, i.diploma, i.category,
               DATE_FORMAT(i.closingDate, '%Y-%m-%d') AS closingDate,
               (i.closingDate BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 3 DAY)) AS closingSoon,
               EXISTS (
                   SELECT 1 FROM saved_internships s
                   WHERE s.userId = ? AND s.internshipId = i.internshipId
               ) AS isSaved
               FROM internships i`;
    let values = [req.session.user.userId];
    const conditions = [];

    if (school || req.session.user.role === 'student') {
        conditions.push('i.school = ?');
        values.push(school);
    }
    if (diploma) {
        conditions.push('i.diploma = ?');
        values.push(diploma);
    }
    if (category) {
        conditions.push('i.category = ?');
        values.push(category);
    }
    if (search) {
        conditions.push('(i.companyName LIKE ? OR i.jobTitle LIKE ? OR i.location LIKE ?)');
        values.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }
    if (conditions.length > 0) {
        sql += ' WHERE ' + conditions.join(' AND ');
    }
    sql += ' ORDER BY i.internshipId DESC';

    connection.query(sql, values, (error, results) => {
        if (error) {
            console.error('Internship list error:', error.message);
            return res.send('Error retrieving internships');
        }

        res.render('internships', {
            internships: results,
            search,
            selectedSchool: school,
            selectedDiploma: diploma,
            selectedCategory: category,
            message: req.query.message || null
        });
    });
});

app.get('/internship/:internshipId', checkAuthenticated, (req, res) => {
    let sql = `SELECT i.internshipId, i.companyName, i.jobTitle, i.location,
                 i.allowance, i.description, i.requirements, i.school, i.diploma, i.category,
                 DATE_FORMAT(i.closingDate, '%Y-%m-%d') AS closingDate,
                 (i.closingDate IS NULL OR i.closingDate >= CURDATE()) AS isOpen,
                 (i.closingDate BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 3 DAY)) AS closingSoon,
                 EXISTS (
                     SELECT 1 FROM applications a
                     WHERE a.userId = ? AND a.internshipId = i.internshipId
                 ) AS hasApplied,
                 EXISTS (
                     SELECT 1 FROM saved_internships s
                     WHERE s.userId = ? AND s.internshipId = i.internshipId
                 ) AS isSaved
                 FROM internships i
                 WHERE i.internshipId = ?`;
    const values = [req.session.user.userId, req.session.user.userId, req.params.internshipId];

    if (req.session.user.role === 'student') {
        sql += ' AND i.school = ?';
        values.push(req.session.user.school);
    }

    connection.query(
        sql,
        values,
        (error, results) => {
            if (error) {
                console.error('Internship details error:', error.message);
                return res.send('Error retrieving internship');
            }
            if (results.length === 0) {
                return res.status(404).render('error', { message: 'Internship not found.' });
            }
            res.render('internship', {
                internship: results[0],
                hasApplied: results[0].hasApplied === 1,
                message: req.query.message || null,
                error: req.query.error || null
            });
        }
    );
});

// Zelia - Internship CRUD
app.get('/addInternship', checkAuthenticated, checkAdmin, (req, res) => {
    res.render('addInternship', { error: null, formData: {} });
});

app.post('/addInternship', checkAuthenticated, checkAdmin, (req, res) => {
    const { companyName, jobTitle, description, location, allowance, requirements,
        closingDate, school, diploma, category } = req.body;

    if (!companyName || !jobTitle || !description || !location || !school || !diploma || !category) {
        return res.render('addInternship', {
            error: 'Company, job title, description, location, school, diploma and category are required.',
            formData: req.body
        });
    }
    if (!isValidSchoolAndDiploma(school, diploma) || !internshipCategories.includes(category)) {
        return res.render('addInternship', {
            error: 'Please select a valid school, diploma and category.',
            formData: req.body
        });
    }

    const sql = `INSERT INTO internships
                 (companyName, jobTitle, description, location, allowance, requirements,
                  closingDate, school, diploma, category)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
    const values = [companyName, jobTitle, description, location, allowance || null,
        requirements || null, closingDate || null, school, diploma, category];

    connection.query(sql, values, (error) => {
        if (error) {
            console.error('Add internship error:', error.message);
            return res.send('Error adding internship');
        }
        res.redirect('/internships?message=Internship+added+successfully.');
    });
});

// Edit internship - admin only
app.get('/editInternship/:internshipId', checkAuthenticated, checkAdmin, (req, res) => {
    const sql = `SELECT internshipId, companyName, jobTitle, description, location,
                 allowance, requirements, school, diploma, category,
                 DATE_FORMAT(closingDate, '%Y-%m-%d') AS closingDate
                 FROM internships WHERE internshipId = ?`;

    connection.query(sql, [req.params.internshipId], (error, results) => {
        if (error) {
            console.error('Edit internship page error:', error.message);
            return res.send('Error retrieving internship');
        }
        if (results.length === 0) {
            return res.status(404).render('error', { message: 'Internship not found.' });
        }
        res.render('editInternship', { internship: results[0], error: null });
    });
});

app.post('/editInternship/:internshipId', checkAuthenticated, checkAdmin, (req, res) => {
    const { companyName, jobTitle, description, location, allowance, requirements,
        closingDate, school, diploma, category } = req.body;

    if (!companyName || !jobTitle || !description || !location || !school || !diploma || !category) {
        return res.render('editInternship', {
            internship: { internshipId: req.params.internshipId, ...req.body },
            error: 'Company, job title, description, location, school, diploma and category are required.'
        });
    }
    if (!isValidSchoolAndDiploma(school, diploma) || !internshipCategories.includes(category)) {
        return res.render('editInternship', {
            internship: { internshipId: req.params.internshipId, ...req.body },
            error: 'Please select a valid school, diploma and category.'
        });
    }

    const sql = `UPDATE internships
                 SET companyName = ?, jobTitle = ?, description = ?, location = ?,
                 allowance = ?, requirements = ?, closingDate = ?, school = ?,
                 diploma = ?, category = ?
                 WHERE internshipId = ?`;
    const values = [companyName, jobTitle, description, location, allowance || null,
        requirements || null, closingDate || null, school, diploma, category,
        req.params.internshipId];

    connection.query(sql, values, (error) => {
        if (error) {
            console.error('Update internship error:', error.message);
            return res.send('Error updating internship');
        }
        res.redirect('/internships?message=Internship+updated+successfully.');
    });
});

app.post('/deleteInternship/:internshipId', checkAuthenticated, checkAdmin, (req, res) => {
    const sql = 'DELETE FROM internships WHERE internshipId = ?';
    connection.query(sql, [req.params.internshipId], (error) => {
        if (error) {
            console.error('Delete internship error:', error.message);
            return res.send('This internship cannot be deleted while it has applications.');
        }
        res.redirect('/internships?message=Internship+deleted+successfully.');
    });
});

// =====================================================
// Done By: YAP CHIEN TING QUINA 25041331
// QUINA
// Internship Searching, Filtering
// and Saved Internship Management
// =====================================================
// Search and filtering are inside GET /internships above because that route is shared with Zelia.
app.post('/saveInternship/:internshipId', checkAuthenticated, checkStudent, (req, res) => {
    const sql = `INSERT INTO saved_internships (userId, internshipId, savedDate)
                 SELECT ?, internshipId, CURDATE() FROM internships
                 WHERE internshipId = ? AND school = ?
                 ON DUPLICATE KEY UPDATE savedId = savedId`;
    connection.query(sql, [req.session.user.userId, req.params.internshipId,
        req.session.user.school], (error, results) => {
        if (error) {
            console.error('Save internship error:', error.message);
            return res.send('Error saving internship');
        }
        if (results.affectedRows === 0) {
            return res.status(404).render('error', { message: 'Internship not found.' });
        }
        res.redirect('/internships?message=Internship+saved.');
    });
});

app.post('/unsaveInternship/:internshipId', checkAuthenticated, checkStudent, (req, res) => {
    const sql = 'DELETE FROM saved_internships WHERE userId = ? AND internshipId = ?';
    connection.query(sql, [req.session.user.userId, req.params.internshipId], (error) => {
        if (error) {
            console.error('Unsave internship error:', error.message);
            return res.send('Error removing saved internship');
        }
        res.redirect(req.body.from === 'saved' ? '/savedInternships' : '/internships');
    });
});

app.get('/savedInternships', checkAuthenticated, checkStudent, (req, res) => {
    const sql = `SELECT i.internshipId, i.companyName, i.jobTitle, i.location, i.allowance,
                 DATE_FORMAT(i.closingDate, '%Y-%m-%d') AS closingDate,
                 (i.closingDate BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 3 DAY)) AS closingSoon
                 FROM saved_internships s
                 JOIN internships i ON s.internshipId = i.internshipId
                 WHERE s.userId = ? AND i.school = ?
                 ORDER BY s.savedId DESC`;

    connection.query(sql, [req.session.user.userId, req.session.user.school], (error, results) => {
        if (error) {
            console.error('Saved internships error:', error.message);
            return res.send('Error retrieving saved internships');
        }
        res.render('savedInternships', { internships: results });
    });
});


// ==========================================
// Done By: SHAWN TAY YAO TING 25044598
// Feature: Resume Upload and PDF Validation
// ==========================================
const storage = multer.diskStorage({
    destination: path.join(__dirname, 'public/uploads'),
    filename: (req, file, callback) => {
        let fileName = path.parse(file.originalname).name;
        fileName = fileName.replace(/[^a-zA-Z0-9_-]/g, '-').slice(0, 150);
        callback(null, Date.now() + '-' + req.session.user.userId + '-' + fileName + '.pdf');
    }
});

const upload = multer({
    storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, callback) => {
        const isPdf = file.mimetype === 'application/pdf' &&
            path.extname(file.originalname).toLowerCase() === '.pdf';

        if (!isPdf) {
            return callback(new Error('Only PDF files are allowed.'));
        }
        callback(null, true);
    }
});

// =====================================================
// Done By: SHAWN TAY YAO TING 25044598
// Student Profile, Resume Management
// and Internship Application Submission
// =====================================================
// Resume upload configuration is kept in shared setup because upload.single(...) uses it.
// Shawn - Student profile and resume management
app.get('/profile', checkAuthenticated, checkStudent, (req, res) => {
    const sql = `SELECT name AS username, email, school, diploma
                 FROM users WHERE userId = ?`;
    connection.query(sql, [req.session.user.userId], (error, results) => {
        if (error) {
            console.error('Profile error:', error.message);
            return res.send('Error retrieving profile');
        }
        if (results.length === 0) {
            return res.status(404).render('error', { message: 'User not found.' });
        }
        const documentSql = `SELECT documentId, resumeName, fileName, documentType,
                             DATE_FORMAT(uploadedAt, '%Y-%m-%d %H:%i') AS uploadedAt
                             FROM documents WHERE userId = ?
                             ORDER BY documentId DESC`;
        connection.query(documentSql, [req.session.user.userId], (documentError, documents) => {
            if (documentError) {
                console.error('Documents error:', documentError.message);
                return res.send('Error retrieving documents');
            }
            res.render('profile', {
                profile: results[0],
                documents,
                message: req.query.message || null,
                error: req.query.error || null
            });
        });
    });
});

app.post('/uploadResume', checkAuthenticated, checkStudent, (req, res) => {
    upload.single('resume')(req, res, (uploadError) => {
        if (uploadError) {
            return res.redirect('/profile?error=' + encodeURIComponent(uploadError.message));
        }
        if (!req.file) {
            return res.redirect('/profile?error=Please+select+a+PDF+file.');
        }

        const resumeName = (req.body.resumeName || path.parse(req.file.originalname).name).trim();
        if (resumeName.length > 100) {
            fs.unlink(req.file.path, () => {});
            return res.redirect('/profile?error=Resume+name+must+not+exceed+100+characters.');
        }

        const sql = `INSERT INTO documents
                     (userId, resumeName, fileName, storedFileName, filePath, documentType)
                     VALUES (?, ?, ?, ?, ?, ?)`;
        const values = [req.session.user.userId, resumeName, req.file.originalname.slice(0, 255),
            req.file.filename, `public/uploads/${req.file.filename}`, 'Resume'];

        connection.query(sql, values, (error) => {
            if (error) {
                console.error('Resume update error:', error.message);
                fs.unlink(req.file.path, () => {});
                return res.send('Error saving resume');
            }
            res.redirect('/profile?message=Resume+uploaded+successfully.');
        });
    });
});

app.get('/document/:documentId', checkAuthenticated, (req, res) => {
    let sql = `SELECT d.fileName, d.filePath FROM documents d
               WHERE d.documentId = ?`;
    let values = [req.params.documentId];

    if (req.session.user.role === 'student') {
        sql += ' AND d.userId = ?';
        values.push(req.session.user.userId);
    } else if (req.session.user.role === 'admin') {
        sql += ` AND EXISTS (
                    SELECT 1 FROM applications a WHERE a.resumeId = d.documentId
                 )`;
    } else {
        return res.status(403).render('error', { message: 'Access denied.' });
    }

    connection.query(sql, values, (error, results) => {
        if (error) {
            console.error('View document error:', error.message);
            return res.send('Error retrieving document');
        }
        if (results.length === 0) {
            return res.status(404).render('error', { message: 'Document not found.' });
        }

        const uploadsFolder = path.resolve(__dirname, 'public/uploads');
        const filePath = path.resolve(__dirname, results[0].filePath);
        if (!filePath.startsWith(uploadsFolder + path.sep) || !fs.existsSync(filePath)) {
            return res.status(404).render('error', { message: 'Document file not found.' });
        }
        res.sendFile(filePath);
    });
});

app.post('/deleteDocument/:documentId', checkAuthenticated, checkStudent, (req, res) => {
    const selectSql = 'SELECT filePath FROM documents WHERE documentId = ? AND userId = ?';
    const values = [req.params.documentId, req.session.user.userId];

    connection.query(selectSql, values, (selectError, results) => {
        if (selectError) {
            console.error('Document lookup error:', selectError.message);
            return res.send('Error retrieving document');
        }
        if (results.length === 0) {
            return res.status(404).render('error', { message: 'Document not found.' });
        }

        const deleteSql = 'DELETE FROM documents WHERE documentId = ? AND userId = ?';
        connection.query(deleteSql, values, (error) => {
            if (error) {
                if (error.code === 'ER_ROW_IS_REFERENCED_2') {
                    return res.redirect('/profile?error=This+resume+is+attached+to+an+application+and+cannot+be+deleted.');
                }
                console.error('Delete document error:', error.message);
                return res.send('Error deleting document');
            }

            const uploadsFolder = path.resolve(__dirname, 'public/uploads');
            const filePath = path.resolve(__dirname, results[0].filePath);
            if (filePath.startsWith(uploadsFolder + path.sep)) {
                fs.unlink(filePath, (fileError) => {
                    if (fileError && fileError.code !== 'ENOENT') {
                        console.error('Delete file error:', fileError.message);
                    }
                });
            }
            res.redirect('/profile?message=Document+deleted+successfully.');
        });
    });
});

// Shawn - Resume selection and application form
app.get('/apply/:internshipId', checkAuthenticated, checkStudent, (req, res) => {
    const sql = `SELECT i.internshipId, i.companyName, i.jobTitle,
                 DATE_FORMAT(i.closingDate, '%Y-%m-%d') AS closingDate,
                 (i.closingDate IS NULL OR i.closingDate >= CURDATE()) AS isOpen,
                 EXISTS (
                     SELECT 1 FROM applications a
                     WHERE a.userId = ? AND a.internshipId = i.internshipId
                 ) AS hasApplied
                 FROM internships i
                 WHERE i.internshipId = ? AND i.school = ?`;

    connection.query(sql, [req.session.user.userId, req.params.internshipId,
        req.session.user.school], (error, results) => {
        if (error) {
            console.error('Application form error:', error.message);
            return res.send('Error retrieving internship');
        }
        if (results.length === 0) {
            return res.status(404).render('error', { message: 'Internship not found.' });
        }
        if (results[0].hasApplied === 1) {
            return res.redirect(`/internship/${req.params.internshipId}?error=You+have+already+applied.`);
        }
        if (results[0].isOpen !== 1) {
            return res.redirect(`/internship/${req.params.internshipId}?error=Applications+are+closed.`);
        }
        const documentSql = `SELECT documentId, resumeName, fileName, documentType
                             FROM documents WHERE userId = ?
                             ORDER BY documentId DESC`;
        connection.query(documentSql, [req.session.user.userId], (documentError, documents) => {
            if (documentError) {
                console.error('Application documents error:', documentError.message);
                return res.send('Error retrieving documents');
            }
            res.render('apply', {
                internship: results[0],
                documents,
                error: req.query.error || null
            });
        });
    });
});

// Shawn - Application submission, ownership checks and initial pending status
app.post('/apply/:internshipId', checkAuthenticated, checkStudent, (req, res) => {
    const userId = req.session.user.userId;
    const internshipId = req.params.internshipId;
    const resumeId = req.body.resumeId;
    const coverLetter = (req.body.coverLetter || '').trim();

    if (!resumeId) {
        return res.redirect(`/apply/${internshipId}?error=Please+select+a+resume.`);
    }
    if (coverLetter.length > 1000) {
        return res.redirect(`/apply/${internshipId}?error=Cover+letter+must+not+exceed+1000+characters.`);
    }

    const documentSql = 'SELECT documentId FROM documents WHERE documentId = ? AND userId = ?';
    connection.query(documentSql, [resumeId, userId], (documentError, documentResults) => {
        if (documentError) {
            console.error('Resume check error:', documentError.message);
            return res.send('Error checking resume');
        }
        if (documentResults.length === 0) {
            return res.redirect(`/apply/${internshipId}?error=Invalid+resume+selection.`);
        }

        const internshipSql = `SELECT internshipId FROM internships
                               WHERE internshipId = ? AND school = ?
                               AND (closingDate IS NULL OR closingDate >= CURDATE())`;
        connection.query(internshipSql, [internshipId, req.session.user.school], (internshipError, internshipResults) => {
            if (internshipError) {
                console.error('Internship check error:', internshipError.message);
                return res.send('Error checking internship');
            }
            if (internshipResults.length === 0) {
                return res.redirect(`/internship/${internshipId}?error=Internship+not+found+or+applications+are+closed.`);
            }

            const duplicateSql = 'SELECT applicationId FROM applications WHERE userId = ? AND internshipId = ?';
            connection.query(duplicateSql, [userId, internshipId], (duplicateError, duplicateResults) => {
                if (duplicateError) {
                    console.error('Duplicate application check error:', duplicateError.message);
                    return res.send('Error checking application');
                }
                if (duplicateResults.length > 0) {
                    return res.redirect(`/internship/${internshipId}?error=You+have+already+applied.`);
                }

                const insertSql = `INSERT INTO applications
                                   (userId, internshipId, resumeId, coverLetter, status, applicationDate)
                                   VALUES (?, ?, ?, ?, ?, CURDATE())`;
                const values = [userId, internshipId, resumeId, coverLetter || null, 'Pending'];

                connection.query(insertSql, values, (error, results) => {
                    if (error) {
                        if (error.code === 'ER_DUP_ENTRY') {
                            return res.redirect(`/internship/${internshipId}?error=You+have+already+applied.`);
                        }
                        console.error('Application error:', error.message);
                        return res.send('Error submitting application');
                    }

                    const historySql = `INSERT INTO application_status_history
                                        (applicationId, status) VALUES (?, ?)`;
                    connection.query(historySql, [results.insertId, 'Pending'], (historyError) => {
                        if (historyError) {
                            console.error('Application history error:', historyError.message);
                            return res.send('Application submitted, but status history could not be saved');
                        }
                        res.redirect(`/internship/${internshipId}?message=Application+submitted+successfully.`);
                    });
                });
            });
        });
    });
});

// =====================================================
// Done By: WONG ZHI LI 25033271
// Application Tracking, Status Management,
// Interviews and Offer Management
// =====================================================
app.get('/tracker', checkAuthenticated, checkStudent, (req, res) => {
    const userId = req.session.user.userId;
    const statsSql = `SELECT status, COUNT(*) AS total
                      FROM applications
                      WHERE userId = ?
                      GROUP BY status`;

    connection.query(statsSql, [userId], (statsError, statusResults) => {
        if (statsError) {
            console.error('Tracker statistics error:', statsError.message);
            return res.send('Error retrieving tracker statistics');
        }

        const stats = {
            total: 0,
            Pending: 0,
            Shortlisted: 0,
            Interview: 0,
            Offered: 0,
            Accepted: 0,
            Rejected: 0
        };

        for (const row of statusResults) {
            stats.total += Number(row.total);
            if (stats[row.status] !== undefined) {
                stats[row.status] = Number(row.total);
            }
        }

        const sql = `SELECT a.status,
                     DATE_FORMAT(a.applicationDate, '%Y-%m-%d') AS appliedDate,
                     i.companyName, i.jobTitle
                     FROM applications a
                     JOIN internships i ON a.internshipId = i.internshipId
                     WHERE a.userId = ?
                     ORDER BY a.applicationId DESC`;

        connection.query(sql, [userId], (error, results) => {
            if (error) {
                console.error('Tracker applications error:', error.message);
                return res.send('Error retrieving applications');
            }
            res.render('tracker', { stats, applications: results });
        });
    });
});
app.get('/myApplications', checkAuthenticated, checkStudent, (req, res) => {
    const sql = `SELECT a.applicationId, a.status,
                 DATE_FORMAT(a.applicationDate, '%Y-%m-%d') AS appliedDate,
                 DATE_FORMAT(a.interviewDate, '%Y-%m-%d') AS interviewDate,
                 DATE_FORMAT(a.interviewTime, '%H:%i') AS interviewTime,
                 a.interviewLocation, a.meetingLink, a.interviewNotes,
                 i.companyName, i.jobTitle, i.location
                 FROM applications a
                 JOIN internships i ON a.internshipId = i.internshipId
                 WHERE a.userId = ?
                 ORDER BY a.applicationId DESC`;

    connection.query(sql, [req.session.user.userId], (error, results) => {
        if (error) {
            console.error('My applications error:', error.message);
            return res.send('Error retrieving applications');
        }
        res.render('myApplications', {
            applications: results,
            message: req.query.message || null,
            error: req.query.error || null
        });
    });
});

// Application Status History
app.get('/application/:applicationId/history', checkAuthenticated, (req, res) => {
    let applicationSql = `SELECT a.applicationId, a.status, a.userId,
                          u.name AS username, i.companyName, i.jobTitle
                          FROM applications a
                          JOIN users u ON a.userId = u.userId
                          JOIN internships i ON a.internshipId = i.internshipId
                          WHERE a.applicationId = ?`;
    let values = [req.params.applicationId];

    if (req.session.user.role === 'student') {
        applicationSql += ' AND a.userId = ?';
        values.push(req.session.user.userId);
    } else if (req.session.user.role !== 'admin') {
        return res.status(403).render('error', { message: 'Access denied.' });
    }

    connection.query(applicationSql, values, (applicationError, applicationResults) => {
        if (applicationError) {
            console.error('Application history lookup error:', applicationError.message);
            return res.send('Error retrieving application');
        }
        if (applicationResults.length === 0) {
            return res.status(404).render('error', { message: 'Application not found.' });
        }

        const historySql = `SELECT status,
                            DATE_FORMAT(changedDate, '%Y-%m-%d %H:%i') AS changedDate
                            FROM application_status_history
                            WHERE applicationId = ?
                            ORDER BY changedDate, historyId`;
        connection.query(historySql, [req.params.applicationId], (error, history) => {
            if (error) {
                console.error('Application history error:', error.message);
                return res.send('Error retrieving application history');
            }
            res.render('applicationHistory', {
                application: applicationResults[0],
                history
            });
        });
    });
});

// Jerry - Offer acceptance and rejection
function saveOfferResponse(req, res, newStatus) {
    const sql = `UPDATE applications SET status = ?
                 WHERE applicationId = ? AND userId = ? AND status = 'Offered'`;
    const values = [newStatus, req.params.applicationId,
        req.session.user.userId];

    connection.query(sql, values, (error, results) => {
        if (error) {
            console.error('Offer response error:', error.message);
            return res.send('Error responding to offer');
        }
        if (results.affectedRows === 0) {
            return res.redirect('/myApplications?error=Offer+not+found+or+already+answered.');
        }

        const historySql = `INSERT INTO application_status_history
                            (applicationId, status) VALUES (?, ?)`;
        connection.query(historySql, [req.params.applicationId, newStatus], (historyError) => {
            if (historyError) {
                console.error('Offer history error:', historyError.message);
                return res.send('Offer updated, but status history could not be saved');
            }
            res.redirect('/myApplications?message=Offer+response+saved.');
        });
    });
}

app.post('/application/:applicationId/acceptOffer', checkAuthenticated, checkStudent, (req, res) => {
    saveOfferResponse(req, res, 'Accepted');
});

app.post('/application/:applicationId/declineOffer', checkAuthenticated, checkStudent, (req, res) => {
    saveOfferResponse(req, res, 'Rejected');
});

// Admin Application Management
app.get('/applications', checkAuthenticated, checkAdmin, (req, res) => {
    const status = req.query.status || '';
    let sql = `SELECT a.applicationId, a.status,
               DATE_FORMAT(a.applicationDate, '%Y-%m-%d') AS appliedDate,
               DATE_FORMAT(a.interviewDate, '%Y-%m-%d') AS interviewDate,
               DATE_FORMAT(a.interviewTime, '%H:%i') AS interviewTime,
               a.interviewLocation, a.meetingLink, a.interviewNotes,
               a.coverLetter, d.documentId AS resumeId,
               COALESCE(NULLIF(d.resumeName, ''), d.fileName) AS resumeFileName,
               u.name AS username, u.email,
               i.companyName, i.jobTitle
               FROM applications a
               JOIN users u ON a.userId = u.userId
               JOIN internships i ON a.internshipId = i.internshipId
               LEFT JOIN documents d ON a.resumeId = d.documentId`;
    let values = [];

    if (status) {
        sql += ' WHERE a.status = ?';
        values = [status];
    }
    sql += ' ORDER BY a.applicationId DESC';

    connection.query(sql, values, (error, results) => {
        if (error) {
            console.error('Applications list error:', error.message);
            return res.send('Error retrieving applications');
        }
        res.render('applications', {
            applications: results,
            selectedStatus: status,
            message: req.query.message || null
        });
    });
});

app.post('/updateApplication/:applicationId', checkAuthenticated, checkAdmin, (req, res) => {
    const allowedStatuses = ['Pending', 'Shortlisted', 'Interview', 'Offered', 'Accepted', 'Rejected'];

    if (!allowedStatuses.includes(req.body.status)) {
        return res.status(400).render('error', { message: 'Invalid application status.' });
    }

    let sql = 'UPDATE applications SET status = ? WHERE applicationId = ?';
    let values = [req.body.status, req.params.applicationId];

    if (req.body.status === 'Interview') {
        const { interviewDate, interviewTime, interviewLocation, meetingLink, interviewNotes } = req.body;

        if (!interviewDate || !interviewTime || (!interviewLocation && !meetingLink)) {
            return res.status(400).render('error', {
                message: 'Interview date, time and a location or meeting link are required.'
            });
        }
        if (meetingLink && !/^https?:\/\//i.test(meetingLink)) {
            return res.status(400).render('error', {
                message: 'Meeting link must start with http:// or https://.'
            });
        }

        sql = `UPDATE applications
               SET status = ?, interviewDate = ?, interviewTime = ?,
               interviewLocation = ?, meetingLink = ?, interviewNotes = ?
               WHERE applicationId = ?`;
        values = [req.body.status, interviewDate, interviewTime,
            interviewLocation || null, meetingLink || null,
            interviewNotes || null, req.params.applicationId];
    }

    connection.query(sql, values, (error, results) => {
        if (error) {
            console.error('Application status error:', error.message);
            return res.send('Error updating application status');
        }
        if (results.affectedRows === 0) {
            return res.status(404).render('error', { message: 'Application not found.' });
        }

        const historySql = `INSERT INTO application_status_history
                            (applicationId, status) VALUES (?, ?)`;
        connection.query(historySql, [req.params.applicationId, req.body.status], (historyError) => {
            if (historyError) {
                console.error('Status history error:', historyError.message);
                return res.send('Application updated, but status history could not be saved');
            }
            res.redirect('/applications?message=Application+updated.');
        });
    });
});

// =====================================================
// UNASSIGNED / GENERAL APPLICATION CODE
// =====================================================
app.get('/', (req, res) => {
    res.render('index', { user: req.session.user || null });
});

// Ownership note: The contribution record does not assign the withdrawal feature
// to a specific team member, so no student is named for this route.
app.post('/withdrawApplication/:applicationId', checkAuthenticated, checkStudent, (req, res) => {
    const sql = 'DELETE FROM applications WHERE applicationId = ? AND userId = ?';
    const values = [req.params.applicationId, req.session.user.userId];

    connection.query(sql, values, (error) => {
        if (error) {
            console.error('Withdraw application error:', error.message);
            return res.send('Error withdrawing application');
        }
        res.redirect('/myApplications?message=Application+withdrawn+successfully.');
    });
});

app.use((req, res) => {
    res.status(404).render('error', {
        message: 'Page not found.',
        user: req.session.user || null
    });
});

// =====================================================
// SERVER STARTUP
// =====================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server started on http://localhost:${PORT}`);
});
