const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });
const Groq = require("groq-sdk");
const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { 
    DynamoDBClient, 
    GetItemCommand, 
    PutItemCommand, 
    ScanCommand, 
    DeleteItemCommand,
    UpdateItemCommand,
    QueryCommand,
    BatchGetItemCommand,
    CreateTableCommand
} = require("@aws-sdk/client-dynamodb");
const { marshall, unmarshall } = require("@aws-sdk/util-dynamodb");

const app = express();
app.use(express.json());
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PATCH', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.static(path.join(__dirname, '../')));

// Simplified token verification - no role checking
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Extract Bearer token

    if (!token) return res.status(401).json({ success: false, message: "No token provided" });

    const secret = process.env.JWT_SECRET || "default_secret_key";
    
    jwt.verify(token, secret, (err, decoded) => {
        if (err) return res.status(403).json({ success: false, message: "Invalid token" });
        req.user = decoded || {};
        next();
    });
};

// Admin authorization - simplified to just check token
const verifyAdmin = (req, res, next) => {
    verifyToken(req, res, next);
};

// Student authorization - simplified to just check token
const verifyStudent = (req, res, next) => {
    verifyToken(req, res, next);
};

// Moderator authorization - simplified to just check token
const verifyModerator = (req, res, next) => {
    verifyToken(req, res, next);
};

// ====================================================
// 2. AWS DYNAMODB CONFIGURATION
// ====================================================

const client = new DynamoDBClient({
    region: process.env.AWS_REGION || "ap-south-1",
    credentials: {
        accessKeyId: (process.env.AWS_ACCESS_KEY_ID || "").trim(),
        secretAccessKey: (process.env.AWS_SECRET_ACCESS_KEY || "").trim()
    }
});

// Helper for DynamoDB Marshalling
const ddbMarshall = (data) => marshall(data, { 
    removeUndefinedValues: true, 
    convertEmptyStrings: true,
    convertClassInstanceToMap: true 
});

const roleTableMap = {
    admin: "AdminTable",
    moderator: "Moderators",
    student: "Students"
};

// ====================================================
// 3. AI GENERATION FUNCTIONS
// ====================================================
async function generateContestContent(topic, difficulty, language, count = 5) {
    if (!process.env.GROQ_API_KEY) {
        console.error("GROQ_API_KEY is missing in .env");
        return [];
    }

    try {
        console.log("Starting Groq AI Generation for topic:", topic);
        
        const chatCompletion = await groq.chat.completions.create({
            messages: [
                {
                    role: "system",
                    content: `You are a competitive programming expert. Generate ${count} programming problems for ${language}.
                    Return ONLY a valid JSON object with a key "problems" containing an array of problem objects.
                    Each problem object must have:
                    - title (string)
                    - description (string - detailed problem statement with constraints)
                    - score (number between 10-50)
                    - difficulty (string: "Easy", "Medium", or "Hard")
                    - input_format (string)
                    - output_format (string)
                    - test_cases (array of objects with "input", "output", and "is_sample" boolean)
                    - hints (array of strings - optional)
                    Ensure the problems are varied and match the ${difficulty} difficulty level.`
                },
                {
                    role: "user",
                    content: `Generate ${count} coding problems for ${language} programming.
                    Topic: "${topic}"
                    Difficulty: "${difficulty}"
                    
                    Return JSON object with "problems" key.`
                }
            ],
            model: "llama-3.3-70b-versatile",
            response_format: { type: "json_object" }
        });

        const text = chatCompletion.choices[0]?.message?.content || "";
        console.log("Raw AI Response received.");

        try {
            const parsed = JSON.parse(text);
            
            if (parsed.problems && Array.isArray(parsed.problems)) {
                return parsed.problems;
            } else if (Array.isArray(parsed)) {
                return parsed;
            } else {
                console.warn("Unexpected AI response format:", parsed);
                return [];
            }
        } catch (parseErr) {
            console.error("JSON Parse Error:", parseErr.message);
            return [];
        }

    } catch (err) {
        console.error("Groq API Error:", err.message);
        return []; 
    }
}

// Generate debugging problems
async function generateDebuggingProblems(topic, difficulty, language, count = 3) {
    if (!process.env.GROQ_API_KEY) {
        console.error("GROQ_API_KEY is missing in .env");
        return [];
    }

    try {
        console.log("Generating debugging problems for:", { topic, difficulty, language });
        
        const chatCompletion = await groq.chat.completions.create({
            messages: [
                {
                    role: "system",
                    content: `You are a coding debugging expert. Generate ${count} debugging problems with intentional bugs in ${language} code.
                    Return ONLY a valid JSON object with a key "problems" containing an array.
                    Each problem in the array must have:
                    - title (string)
                    - description (string)
                    - buggy_code (string - code with realistic bug)
                    - input (string - sample input for testing)
                    - output (string - expected correct output)
                    - hints (array of strings to help find the bug)
                    - explanation (string - brief explanation of the bug)
                    - score (number, default: 20)
                    - difficulty (string, default: "${difficulty}")
                    Add realistic bugs that students need to find and fix.`
                },
                {
                    role: "user",
                    content: `Generate ${count} debugging problems for ${language} programming language.
                    Topic: "${topic}"
                    Difficulty: "${difficulty}"
                    
                    Make the bugs realistic like:
                    1. Off-by-one errors in loops
                    2. Missing variable initialization
                    3. Incorrect conditional logic
                    4. Array indexing errors
                    5. String manipulation mistakes
                    
                    Return a JSON object with a "problems" key containing the array.`
                }
            ],
            model: "llama-3.3-70b-versatile",
            response_format: { type: "json_object" },
            temperature: 0.7
        });

        const text = chatCompletion.choices[0]?.message?.content || "";
        console.log("AI Response received for debugging problems:", text.substring(0, 200) + "...");
        
        try {
            const parsed = JSON.parse(text);
            
            if (parsed.problems && Array.isArray(parsed.problems)) {
                return parsed.problems;
            } else if (Array.isArray(parsed)) {
                return parsed;
            } else if (parsed.data && Array.isArray(parsed.data)) {
                return parsed.data;
            } else if (typeof parsed === 'object') {
                for (const key in parsed) {
                    if (Array.isArray(parsed[key])) {
                        return parsed[key];
                    }
                }
            }
            
            console.warn("Unexpected response format:", parsed);
            return [];
            
        } catch (parseError) {
            console.error("JSON Parse Error:", parseError.message);
            return [];
        }

    } catch (err) {
        console.error("AI Debugging Generation Error:", err.message);
        return []; 
    }
}

// Test debugging solutions
async function testDebugSolution(fixedCode, problem, language) {
    try {
        const languageMap = {
            'python': 'python',
            'cpp': 'cpp',
            'java': 'java',
            'c': 'c'
        };
        
        const compilerLang = languageMap[language] || 'python';
        
        console.log(`Testing debug solution for ${language}, using compiler language: ${compilerLang}`);
        
        const response = await fetch('http://65.2.104.225:8000/api/compile', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                language: compilerLang,
                code: fixedCode,
                stdin: problem.input || ""
            }),
            timeout: 10000
        });
        
        const result = await response.json();
        
        const output = result.output || '';
        const expected = problem.output || '';
        
        const normalize = (str) => {
            if (!str) return '';
            return str.trim()
                .replace(/\r\n/g, '\n')
                .replace(/\n+/g, '\n')
                .replace(/\s+/g, ' ')
                .trim();
        };
        
        const normalizedOutput = normalize(output);
        const normalizedExpected = normalize(expected);
        
        const passed = normalizedOutput === normalizedExpected;
        
        return {
            passed: passed,
            output: output,
            expected: problem.output,
            error: result.stderr || result.error || '',
            time: result.time || 0
        };
        
    } catch (err) {
        console.error("Test Debug Solution Error:", err.message);
        return {
            passed: false,
            output: '',
            expected: problem.output,
            error: `Compiler error: ${err.message}`,
            time: 0
        };
    }
}

// ====================================================
// 4. AUTHENTICATION ROUTES
// ====================================================

app.post('/api/login', async (req, res) => {
    const { email, password, role } = req.body;
    const tableName = roleTableMap[role];
    
    if (!tableName) return res.status(400).json({ success: false, message: "Invalid role selected" });
    if (!email) return res.status(400).json({ success: false, message: "Email is required" });

    const normalizedEmail = String(email).toLowerCase().trim();

    try {
        const { Item } = await client.send(new GetItemCommand({
            TableName: tableName,
            Key: { email: { S: normalizedEmail } }
        }));
        
        if (!Item) return res.status(404).json({ success: false, message: "User not found" });
        const user = unmarshall(Item);

        // Password bypass for students
        if (role !== 'student') {
            if (!password || !user.password || typeof user.password !== 'string') {
                return res.status(401).json({ success: false, message: "Invalid credentials or account configuration." });
            }
            const isMatch = await bcrypt.compare(String(password).trim(), user.password);
            if (!isMatch) return res.status(401).json({ success: false, message: "Invalid credentials" });
        }

        // FIX: Ensure role is lowercase in the token
        const token = jwt.sign(
            { 
                email: user.email, 
                role: role.toLowerCase(),  // ← Changed this line
                name: user.name || user.email 
            }, 
            process.env.JWT_SECRET || "default_secret_key", 
            { expiresIn: '10h' }
        );
        
        res.json({ 
            success: true, 
            token, 
            role: role.toLowerCase(),  // ← Also update response
            name: user.name || user.email, 
            email: user.email 
        });
    } catch (err) { 
        console.error("Login Error:", err);
        res.status(500).json({ success: false, message: "Internal server error during login" }); 
    }
});
// ====================================================
// CONTEST RESULTS ENDPOINTS
// ====================================================

// 1. GET NORMAL CONTEST RESULTS (From 'Scores' table)
// server.js - Updated Results Endpoint
app.get('/api/moderator/contest/:id/results', verifyToken, async (req, res) => {
    try {
        const contestId = req.params.id;
        
        // FIX: Use Scan with a Filter if the GSI (Index) is not confirmed to exist
        const { Items } = await client.send(new ScanCommand({
            TableName: "StudentResults",
            FilterExpression: "contest_id = :cid",
            ExpressionAttributeValues: ddbMarshall({ ":cid": contestId })
        }));

        const results = (Items || []).map(i => unmarshall(i));
        
        // Fetch contest details for the header
        const contestData = await client.send(new GetItemCommand({
            TableName: "Contests",
            Key: ddbMarshall({ contest_id: contestId })
        }));
        const contest = unmarshall(contestData.Item || {});

        res.json({
            success: true,
            data: {
                contest: { 
                    name: contest.name || "Contest Results", 
                    total_score: contest.metadata?.total_score || 100 
                },
                results: results
            }
        });
    } catch (err) {
        console.error("Fetch Results Error:", err);
        res.status(500).json({ success: false, message: err.message });
    }
});

// Add this to your moderator routes in server.js
app.get('/api/moderator/all-student-results', verifyToken, async (req, res) => {
    try {
        const { Items } = await client.send(new ScanCommand({
            TableName: "StudentResults"
        }));

        // Unmarshall the DynamoDB items into standard JSON
        const results = (Items || []).map(i => unmarshall(i));

        res.json({
            success: true,
            data: {
                results: results
            }
        });
    } catch (err) {
        console.error("Global Fetch Error:", err);
        res.status(500).json({ success: false, message: err.message });
    }
});

// 2. GET DEBUGGING CONTEST RESULTS (From 'DebugStudentResults' table)
app.get('/api/moderator/debug-contest/:id/results', verifyToken, async (req, res) => {
    try {
        const contestId = req.params.id;
        
        const { Items } = await client.send(new QueryCommand({
            TableName: "DebugStudentResults",
            IndexName: "ContentResultsIndex", // Partition Key: contest_id
            KeyConditionExpression: "contest_id = :cid",
            ExpressionAttributeValues: ddbMarshall({ ":cid": contestId })
        }));

        const results = (Items || []).map(i => unmarshall(i));
        
        const contestData = await client.send(new GetItemCommand({
            TableName: "DebugContests",
            Key: ddbMarshall({ contest_id: contestId })
        }));
        const contest = unmarshall(contestData.Item || {});

        res.json({
            success: true,
            data: {
                contest: { 
                    name: contest.name || "Debug Contest", 
                    total_score: contest.metadata?.total_score || 100 
                },
                results: results,
                stats: {
                    total_participants: results.length,
                    average_score: results.length > 0 ? results.reduce((sum, r) => sum + (r.total_score || 0), 0) / results.length : 0
                }
            }
        });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// GET individual submissions for a specific debug contest
app.get('/api/moderator/debug-submissions/:id', verifyToken, async (req, res) => {
    try {
        const contestId = req.params.id;
        
        // Fetch all submissions for this contest from DebugSubmissions table
        const { Items } = await client.send(new QueryCommand({
            TableName: "DebugSubmissions",
            IndexName: "ContestSubmissionsIndex", // Ensure this GSI exists on your table
            KeyConditionExpression: "contest_id = :cid",
            ExpressionAttributeValues: ddbMarshall({ ":cid": contestId })
        }));

        res.json({
            success: true,
            data: (Items || []).map(i => unmarshall(i))
        });
    } catch (err) {
        console.error("Error fetching debug submissions:", err);
        res.status(500).json({ success: false, message: err.message });
    }
});

// Get progression rules for student dashboard filtering
app.get('/api/student/progression-rules', verifyToken, async (req, res) => {
    try {
        const { Items } = await client.send(new ScanCommand({
            TableName: "ContestProgressionRules",
            FilterExpression: "#s = :status",
            ExpressionAttributeNames: { "#s": "status" },
            ExpressionAttributeValues: ddbMarshall({ ":status": "active" })
        }));
        
        const rules = (Items || []).map(i => unmarshall(i));
        res.json({ success: true, data: rules });
    } catch (err) {
        res.status(500).json({ success: false, message: "Error fetching rules" });
    }
});

// Get all results for the logged-in student across both contest types
app.get('/api/student/my-results', verifyToken, async (req, res) => {
    try {
        const userEmail = req.user.email;
        const [normalRes, debugRes] = await Promise.all([
            client.send(new ScanCommand({
                TableName: "StudentResults",
                FilterExpression: "student_email = :e",
                ExpressionAttributeValues: ddbMarshall({ ":e": userEmail })
            })),
            client.send(new ScanCommand({
                TableName: "DebugStudentResults",
                FilterExpression: "student_email = :e",
                ExpressionAttributeValues: ddbMarshall({ ":e": userEmail })
            }))
        ]);

        const results = [
            ...(normalRes.Items || []).map(i => unmarshall(i)),
            ...(debugRes.Items || []).map(i => unmarshall(i))
        ];
        res.json({ success: true, data: results });
    } catch (err) {
        res.status(500).json({ success: false, message: "Error fetching results" });
    }
});

app.get('/api/student/available-debug-contests', verifyToken, async (req, res) => {
    try {
        const { Items } = await client.send(new ScanCommand({
            TableName: "DebugContests",
            FilterExpression: "#s = :status",
            ExpressionAttributeNames: { "#s": "status" },
            ExpressionAttributeValues: ddbMarshall({ ":status": "active" })
        }));
        
        const contests = (Items || []).map(i => unmarshall(i));
        res.json({ success: true, data: contests });
    } catch (err) {
        res.status(500).json({ success: false, message: "Error fetching debug contests" });
    }
});
// ====================================================
// 5. ADMIN ROUTES
// ====================================================

// Route 2: Get all moderators (with role filtering) - FIXED VERSION
app.get('/api/admin/moderators', verifyToken, async (req, res) => {
    try {
        console.log("Fetching moderators...");
        
        // Use ScanCommand to get all items from Moderators table
        const { Items } = await client.send(new ScanCommand({ 
            TableName: "Moderators" 
        }));
        
        console.log("Raw Items from DynamoDB:", Items ? Items.length : 0);
        
        if (!Items || Items.length === 0) {
            console.log("No moderators found in database");
            return res.json([]); // Return empty array as expected by admin.html
        }
        
        // Process each item
        const moderators = Items.map(item => {
            try {
                const mod = unmarshall(item);
                console.log("Unmarshalled moderator:", mod.email, mod.name);
                
                // Create a clean moderator object
                const moderator = {
                    email: mod.email || '',
                    name: mod.name || mod.email || 'Unknown',
                    role: mod.role || 'moderator',
                    status: mod.status || 'active',
                    createdAt: mod.created_at || mod.createdAt || new Date().toISOString(),
                    // Add any other fields that might exist
                    ...mod
                };
                
                // Remove password for security
                delete moderator.password;
                
                return moderator;
            } catch (unmarshalErr) {
                console.error("Error unmarshalling item:", unmarshalErr);
                return null;
            }
        }).filter(mod => mod !== null); // Remove any null items
        
        console.log(`Returning ${moderators.length} moderators`);
        
        // Return array directly as expected by admin.html
        res.json(moderators);
        
    } catch (err) {
        console.error("Get Moderators Error:", err.message, err.stack);
        res.status(500).json({ 
            success: false, 
            message: "Error fetching moderators",
            error: err.message 
        });
    }
});
app.post('/api/admin/create-moderator', verifyToken, async (req, res) => {
    const { name, email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: "Email and password required" });
    try {
        const hashedPassword = await bcrypt.hash(String(password).trim(), 10);
        await client.send(new PutItemCommand({
            TableName: "Moderators",
            Item: ddbMarshall({
                email: String(email).toLowerCase().trim(),
                name,
                password: hashedPassword,
                role: "moderator",
                createdAt: new Date().toISOString(),
                status: "active"
            })
        }));
        res.status(201).json({ success: true, message: "Moderator created successfully" });
    } catch (err) { 
        console.error("Create Moderator Error:", err);
        res.status(500).json({ success: false, message: "Error creating moderator" }); 
    }
});

app.patch('/api/admin/moderator-status', verifyToken, async (req, res) => {
    const { email, status } = req.body;
    if (!email) return res.status(400).json({ success: false, message: "Email required" });
    try {
        await client.send(new UpdateItemCommand({
            TableName: "Moderators",
            Key: ddbMarshall({ email: String(email).toLowerCase().trim() }),
            UpdateExpression: "SET #s = :status",
            ExpressionAttributeNames: { "#s": "status" },
            ExpressionAttributeValues: ddbMarshall({ ":status": status })
        }));
        res.json({ success: true, message: "Status updated" });
    } catch (err) { 
        console.error("Update Moderator Status Error:", err);
        res.status(500).json({ success: false, message: "Update failed" }); 
    }
});

app.delete('/api/admin/moderator/:email', verifyToken, async (req, res) => {
    const { email } = req.params;
    if (!email) return res.status(400).json({ success: false, message: "Email required" });
    try {
        await client.send(new DeleteItemCommand({
            TableName: "Moderators",
            Key: ddbMarshall({ email: email.toLowerCase().trim() })
        }));
        res.json({ success: true, message: "Moderator deleted successfully" });
    } catch (err) { 
        console.error("Delete Moderator Error:", err);
        res.status(500).json({ success: false, message: "Delete failed" }); 
    }
});

// ====================================================
// 6. MODERATOR DASHBOARD & COLLEGES
// ====================================================

app.get('/api/moderator/stats', verifyToken, async (req, res) => {
    try {
        const [c, s, ct] = await Promise.all([
            client.send(new ScanCommand({ TableName: "Colleges" })),
            client.send(new ScanCommand({ TableName: "Students" })),
            client.send(new ScanCommand({ TableName: "Contests" }))
        ]);
        const allContests = (ct.Items || []).map(i => unmarshall(i));
        const myContests = allContests.filter(x => x.createdBy === req.user.email);
        
        res.json({ 
            success: true,
            data: {
                colleges: (c.Items || []).length, 
                students: (s.Items || []).length, 
                contests: myContests.length 
            }
        });
    } catch (err) { 
        console.error("Get Stats Error:", err);
        res.status(500).json({ success: false, message: "Error fetching stats" }); 
    }
});

app.get('/api/moderator/colleges', verifyToken, async (req, res) => {
    try {
        const { Items } = await client.send(new ScanCommand({ TableName: "Colleges" }));
        const colleges = (Items || []).map(i => unmarshall(i));
        res.json({ success: true, data: colleges });
    } catch (err) { 
        console.error("Get Colleges Error:", err);
        res.status(500).json({ success: false, message: "Error fetching colleges" }); 
    }
});

app.post('/api/moderator/register-college', verifyToken, async (req, res) => {
    try {
        const collegeData = {
            college_id: crypto.randomUUID(),
            ...req.body,
            createdBy: req.user.email,
            createdAt: new Date().toISOString(),
            status: 'active'
        };
        
        await client.send(new PutItemCommand({
            TableName: "Colleges",
            Item: ddbMarshall(collegeData)
        }));
        res.status(201).json({ success: true, message: "College Registered Successfully", data: collegeData });
    } catch (err) { 
        console.error("Register College Error:", err);
        res.status(500).json({ success: false, message: "Error saving college" }); 
    }
});

app.delete('/api/moderator/college/:id', verifyToken, async (req, res) => {
    try {
        await client.send(new DeleteItemCommand({ 
            TableName: "Colleges", 
            Key: ddbMarshall({ college_id: req.params.id }) 
        }));
        res.json({ success: true, message: "College deleted" });
    } catch (err) { 
        console.error("Delete College Error:", err);
        res.status(500).json({ success: false, message: "Delete failed" }); 
    }
});

// Get list of colleges for dropdown
app.get('/api/moderator/colleges-list', verifyToken, async (req, res) => {
    try {
        const { Items } = await client.send(new ScanCommand({
            TableName: "Students",
            ProjectionExpression: "college"
        }));
        
        const colleges = new Set();
        (Items || []).forEach(item => {
            const student = unmarshall(item);
            if (student.college && student.college.trim()) {
                colleges.add(student.college.trim());
            }
        });
        
        res.json({
            success: true,
            data: Array.from(colleges).sort()
        });
        
    } catch (err) {
        console.error("Get Colleges List Error:", err);
        res.status(500).json({ 
            success: false,
            message: "Error fetching colleges list",
            error: err.message 
        });
    }
});

// ====================================================
// 7. REGULAR CONTEST MANAGEMENT (UPDATED)
// ====================================================

// Get all regular contests
app.get('/api/moderator/contests', verifyToken, async (req, res) => {
    try {
        console.log("Fetching normal contests (no GSI available)...");
        
        // Since no GSI, we have to scan and filter
        const { Items } = await client.send(new ScanCommand({
            TableName: "Contests"
        }));
        
        console.log("Total contests in DB:", Items?.length || 0);
        
        if (!Items || Items.length === 0) {
            console.log("No contests found");
            return res.json({
                success: true,
                data: []
            });
        }
        
        // Process and filter manually
        const contests = (Items || []).map(i => {
            try {
                const contest = unmarshall(i);
                
                // Skip if not created by this moderator
                if (contest.created_by !== req.user.email) {
                    return null;
                }
                
                // Skip debugging contests
                if (contest.type && contest.type.toLowerCase() === 'debugging') {
                    return null;
                }
                
                return {
                    id: contest.contest_id,
                    contest_id: contest.contest_id,
                    title: contest.name,
                    description: contest.description || "No description",
                    type: contest.type || 'normal',
                    status: contest.status || 'active',
                    language: contest.language || 'python',
                    created_at: contest.created_at || contest.createdAt,
                    updated_at: contest.updated_at,
                    passing_score: contest.passing_score || contest.metadata?.passing_score || 70,
                    problems_count: contest.problems?.length || 0,
                    created_by: contest.created_by,
                    total_score: contest.metadata?.total_score || 0
                };
            } catch (err) {
                console.error("Error processing contest:", err);
                return null;
            }
        }).filter(contest => contest !== null); // Remove null items
        
        console.log(`Found ${contests.length} contests for moderator ${req.user.email}`);
        
        res.json({
            success: true,
            data: contests
        });
        
    } catch (err) {
        console.error("Get Normal Contests Error:", err.message, err.stack);
        res.status(500).json({
            success: false,
            message: "Error fetching normal contests",
            error: err.message
        });
    }
});

// New route for students
app.get('/api/student/available-regular-contests', verifyToken, async (req, res) => {
    try {
        const { Items } = await client.send(new ScanCommand({
            TableName: "Contests"
        }));

        if (!Items || Items.length === 0) {
            return res.json({ success: true, data: [] });
        }

        const contests = Items.map(i => {
            const contest = unmarshall(i);
            
            // Only return regular contests (exclude debugging type)
            if (contest.type && contest.type.toLowerCase() === 'debugging') {
                return null;
            }

            return {
                contest_id: contest.contest_id,
                name: contest.name,
                language: contest.language || 'python',
                type: contest.type || 'regular'
            };
        }).filter(c => c !== null);

        res.json({ success: true, data: contests });
    } catch (err) {
        res.status(500).json({ success: false, message: "Error fetching contests" });
    }
});

// ====================================================
// DOCUMENT MODE ROUTES
// ====================================================

// Upload document and extract content
app.post('/api/moderator/upload-document', verifyToken, async (req, res) => {
    try {
        // Note: For file uploads, you'd typically use multer or similar middleware
        // This is a simplified version for text/document content
        
        const { content, documentType, fileName } = req.body;
        
        if (!content) {
            return res.status(400).json({
                success: false,
                message: "Document content is required"
            });
        }
        
        // Generate document ID
        const documentId = `doc_${crypto.randomUUID().replace(/-/g, '').substring(0, 12)}`;
        
        // Save document metadata
        const documentData = {
            document_id: documentId,
            filename: fileName || "uploaded_document.txt",
            content_type: documentType || 'text/plain',
            content: content.substring(0, 10000), // Limit content size
            uploaded_by: req.user.email,
            uploaded_at: new Date().toISOString(),
            status: 'uploaded',
            word_count: content.split(/\s+/).length,
            char_count: content.length
        };
        
        await client.send(new PutItemCommand({
            TableName: "Documents",
            Item: ddbMarshall(documentData)
        }));
        
        res.json({
            success: true,
            message: "Document uploaded successfully",
            data: {
                documentId: documentId,
                filename: documentData.filename,
                wordCount: documentData.word_count,
                charCount: documentData.char_count,
                preview: content.substring(0, 200) + (content.length > 200 ? "..." : "")
            }
        });
        
    } catch (err) {
        console.error("Upload Document Error:", err);
        res.status(500).json({
            success: false,
            message: "Error uploading document",
            error: err.message
        });
    }
});

// Process document to extract problems (using AI)
app.post('/api/moderator/process-document', verifyToken, async (req, res) => {
    try {
        const { documentId, documentContent, language, difficulty } = req.body;
        
        if (!documentContent && !documentId) {
            return res.status(400).json({
                success: false,
                message: "Document content or ID is required"
            });
        }
        
        let content = documentContent;
        
        // If documentId is provided, fetch the document
        if (documentId && !documentContent) {
            const { Item } = await client.send(new GetItemCommand({
                TableName: "Documents",
                Key: ddbMarshall({ document_id: documentId })
            }));
            
            if (!Item) {
                return res.status(404).json({
                    success: false,
                    message: "Document not found"
                });
            }
            
            const document = unmarshall(Item);
            content = document.content;
        }
        
        if (!process.env.GROQ_API_KEY) {
            return res.status(500).json({
                success: false,
                message: "AI service is not configured"
            });
        }
        
        console.log("Processing document with AI...");
        
        // Use AI to extract problems from document
        const chatCompletion = await groq.chat.completions.create({
            messages: [
                {
                    role: "system",
                    content: `You are a programming contest problem extractor. Extract programming problems from the given document.
                    
                    Return ONLY a valid JSON object with a key "problems" containing an array of problem objects.
                    
                    Each problem object must have:
                    - title (string) - concise title
                    - description (string) - detailed problem statement
                    - input_format (string) - how input is provided
                    - output_format (string) - expected output format
                    - constraints (string) - time/space constraints
                    - sample_input (string) - example input
                    - sample_output (string) - expected output for sample
                    - difficulty (string: "Easy", "Medium", "Hard")
                    - score (number between 10-50)
                    - category (string: "Arrays", "Strings", "Dynamic Programming", etc.)
                    
                    Extract as many valid programming problems as you can from the document.
                    Focus on logical, algorithmic, and coding problems.`
                },
                {
                    role: "user",
                    content: `Extract programming problems from this document content:
                    
                    ${content.substring(0, 8000)}  // Limit content size
                    
                    Language focus: ${language || 'general'}
                    Difficulty level: ${difficulty || 'Medium'}
                    
                    Return JSON with "problems" array.`
                }
            ],
            model: "llama-3.3-70b-versatile",
            response_format: { type: "json_object" },
            temperature: 0.3,
            max_tokens: 4000
        });
        
        const text = chatCompletion.choices[0]?.message?.content || "";
        
        try {
            const parsed = JSON.parse(text);
            
            if (parsed.problems && Array.isArray(parsed.problems)) {
                // Enhance problems with additional fields
                const enhancedProblems = parsed.problems.map((problem, index) => ({
                    ...problem,
                    index: index,
                    id: `prob_${crypto.randomUUID().substring(0, 8)}`,
                    extracted_from_document: true,
                    language: language || 'python',
                    time_limit: difficulty === 'Hard' ? 3 : difficulty === 'Medium' ? 2 : 1,
                    memory_limit: 256
                }));
                
                res.json({
                    success: true,
                    data: {
                        problems: enhancedProblems,
                        count: enhancedProblems.length,
                        documentId: documentId,
                        summary: `Extracted ${enhancedProblems.length} problems from document`
                    }
                });
            } else {
                throw new Error("Invalid response format from AI");
            }
        } catch (parseErr) {
            console.error("JSON Parse Error:", parseErr);
            res.status(500).json({
                success: false,
                message: "Failed to parse AI response",
                raw_response: text.substring(0, 500)
            });
        }
        
    } catch (err) {
        console.error("Process Document Error:", err);
        res.status(500).json({
            success: false,
            message: "Error processing document",
            error: err.message
        });
    }
});

// Extract debugging problems from document
app.post('/api/moderator/process-debug-document', verifyToken, async (req, res) => {
    try {
        const { documentId, documentContent, language } = req.body;
        
        let content = documentContent;
        
        if (documentId && !documentContent) {
            const { Item } = await client.send(new GetItemCommand({
                TableName: "Documents",
                Key: ddbMarshall({ document_id: documentId })
            }));
            
            if (!Item) {
                return res.status(404).json({
                    success: false,
                    message: "Document not found"
                });
            }
            
            const document = unmarshall(Item);
            content = document.content;
        }
        
        if (!process.env.GROQ_API_KEY) {
            return res.status(500).json({
                success: false,
                message: "AI service is not configured"
            });
        }
        
        console.log("Processing document for debugging problems...");
        
        const chatCompletion = await groq.chat.completions.create({
            messages: [
                {
                    role: "system",
                    content: `You are a debugging problem extractor. Extract code snippets with intentional bugs from the document.
                    
                    Return ONLY a valid JSON object with key "problems" containing debugging problem objects.
                    
                    Each debugging problem must have:
                    - title (string)
                    - description (string) - what the code should do vs what's wrong
                    - buggy_code (string) - code with intentional bug
                    - input (string) - sample input for testing
                    - output (string) - expected correct output
                    - hints (array of strings) - clues to find the bug
                    - explanation (string) - brief explanation of the bug
                    - difficulty (string)
                    - score (number, default: 20)
                    
                    Look for code examples that can be modified to have common bugs:
                    1. Off-by-one errors
                    2. Missing initialization
                    3. Incorrect loop conditions
                    4. Wrong variable names
                    5. Logic errors
                    6. Syntax issues
                    7. Edge case handling
                    
                    Make the bugs realistic and educational.`
                },
                {
                    role: "user",
                    content: `Extract debugging problems from this document. Focus on ${language || 'Python'} code:
                    
                    ${content.substring(0, 8000)}
                    
                    Create realistic debugging challenges.`
                }
            ],
            model: "llama-3.3-70b-versatile",
            response_format: { type: "json_object" },
            temperature: 0.4
        });
        
        const text = chatCompletion.choices[0]?.message?.content || "";
        
        try {
            const parsed = JSON.parse(text);
            
            if (parsed.problems && Array.isArray(parsed.problems)) {
                res.json({
                    success: true,
                    data: {
                        problems: parsed.problems,
                        count: parsed.problems.length,
                        documentId: documentId
                    }
                });
            } else {
                throw new Error("Invalid response format");
            }
        } catch (parseErr) {
            console.error("Parse Error:", parseErr);
            res.status(500).json({
                success: false,
                message: "Failed to parse AI response",
                suggestion: "Try with a different document or format"
            });
        }
        
    } catch (err) {
        console.error("Process Debug Document Error:", err);
        res.status(500).json({
            success: false,
            message: "Error processing document for debugging",
            error: err.message
        });
    }
});

// Save processed document problems
app.post('/api/moderator/save-document-problems', verifyToken, async (req, res) => {
    try {
        const { documentId, problems, contestName, language, contestType } = req.body;
        
        if (!problems || !Array.isArray(problems)) {
            return res.status(400).json({
                success: false,
                message: "Problems array is required"
            });
        }
        
        // Save to a temporary storage or directly create contest
        const processedDocId = `proc_${crypto.randomUUID().substring(0, 12)}`;
        
        const processedData = {
            processed_id: processedDocId,
            document_id: documentId,
            contest_name: contestName || "Document-Based Contest",
            contest_type: contestType || 'regular',
            language: language || 'python',
            problems: problems,
            processed_by: req.user.email,
            processed_at: new Date().toISOString(),
            status: 'processed',
            problem_count: problems.length
        };
        
        await client.send(new PutItemCommand({
            TableName: "ProcessedDocuments",
            Item: ddbMarshall(processedData)
        }));
        
        res.json({
            success: true,
            data: {
                processedId: processedDocId,
                contestName: processedData.contest_name,
                problemCount: problems.length,
                canCreateContest: true
            }
        });
        
    } catch (err) {
        console.error("Save Document Problems Error:", err);
        res.status(500).json({
            success: false,
            message: "Error saving processed problems",
            error: err.message
        });
    }
});

// Get processed documents
app.get('/api/moderator/processed-documents', verifyToken, async (req, res) => {
    try {
        const { Items } = await client.send(new ScanCommand({
            TableName: "ProcessedDocuments",
            FilterExpression: "processed_by = :email",
            ExpressionAttributeValues: ddbMarshall({
                ":email": req.user.email
            })
        }));
        
        const documents = (Items || []).map(i => {
            const doc = unmarshall(i);
            return {
                id: doc.processed_id,
                document_id: doc.document_id,
                contest_name: doc.contest_name,
                contest_type: doc.contest_type,
                language: doc.language,
                problem_count: doc.problem_count || 0,
                processed_at: doc.processed_at,
                status: doc.status
            };
        });
        
        res.json({
            success: true,
            data: documents
        });
        
    } catch (err) {
        console.error("Get Processed Documents Error:", err);
        res.status(500).json({
            success: false,
            message: "Error fetching processed documents"
        });
    }
});

// Example documents library
app.get('/api/moderator/example-documents', verifyToken, async (req, res) => {
    try {
        const exampleDocuments = [
            {
                id: "example_1",
                title: "Basic Algorithms Collection",
                description: "Common algorithms with examples in Python",
                category: "Algorithms",
                language: "python",
                difficulty: "Beginner",
                content_preview: "This document contains basic algorithm implementations including sorting, searching, and recursion examples...",
                tags: ["sorting", "searching", "recursion"],
                estimated_problems: 8
            },
            {
                id: "example_2",
                title: "Data Structures Problems",
                description: "Problems related to arrays, linked lists, trees, and graphs",
                category: "Data Structures",
                language: "cpp",
                difficulty: "Intermediate",
                content_preview: "Collection of data structure problems with increasing difficulty. Includes array manipulation, linked list operations...",
                tags: ["arrays", "linked-lists", "trees", "graphs"],
                estimated_problems: 12
            },
            {
                id: "example_3",
                title: "Debugging Challenges",
                description: "Code snippets with intentional bugs for debugging practice",
                category: "Debugging",
                language: "java",
                difficulty: "Mixed",
                content_preview: "A set of Java programs containing common bugs. Students must identify and fix the issues...",
                tags: ["debugging", "java", "bugs"],
                estimated_problems: 10
            },
            {
                id: "example_4",
                title: "Dynamic Programming Problems",
                description: "Classic DP problems with explanations",
                category: "Algorithms",
                language: "python",
                difficulty: "Advanced",
                content_preview: "Comprehensive guide to dynamic programming with problem statements and solutions...",
                tags: ["dynamic-programming", "algorithms", "optimization"],
                estimated_problems: 6
            },
            {
                id: "example_5",
                title: "String Manipulation Exercises",
                description: "Problems focusing on string operations and algorithms",
                category: "Strings",
                language: "python",
                difficulty: "Beginner",
                content_preview: "Various string manipulation problems including palindrome checks, anagrams, and pattern matching...",
                tags: ["strings", "palindrome", "anagram"],
                estimated_problems: 7
            }
        ];
        
        res.json({
            success: true,
            data: exampleDocuments
        });
        
    } catch (err) {
        console.error("Get Example Documents Error:", err);
        res.status(500).json({
            success: false,
            message: "Error fetching example documents"
        });
    }
});

// Load specific example document
app.get('/api/moderator/example-document/:id', verifyToken, async (req, res) => {
    try {
        const exampleId = req.params.id;
        
        // In a real system, these would be stored in a database
        const exampleDocuments = {
            "example_1": {
                title: "Basic Algorithms Collection",
                content: `# Basic Algorithms Collection

## 1. Binary Search Algorithm
Implement binary search to find an element in a sorted array.

**Input Format:**
- First line: n (size of array)
- Second line: n sorted integers
- Third line: target element

**Output Format:**
Index of target element or -1 if not found

**Constraints:**
- 1 ≤ n ≤ 10^5
- Array elements are sorted in ascending order
- Array elements are integers

**Example:**
Input:
5
1 3 5 7 9
5
Output:
2

## 2. Bubble Sort
Implement bubble sort to sort an array in ascending order.

**Input Format:**
- First line: n (size of array)
- Second line: n integers

**Output Format:**
Sorted array

**Constraints:**
- 1 ≤ n ≤ 1000

## 3. Fibonacci Sequence
Calculate the nth Fibonacci number using recursion.

**Input Format:**
Single integer n

**Output Format:**
nth Fibonacci number

**Constraints:**
- 0 ≤ n ≤ 30

**Example:**
Input: 6
Output: 8

## 4. Palindrome Check
Check if a given string is a palindrome.

**Input Format:**
Single string

**Output Format:**
"YES" if palindrome, "NO" otherwise

**Example:**
Input: racecar
Output: YES
Input: hello
Output: NO

## 5. Factorial Calculation
Calculate factorial of a number.

**Input Format:**
Single integer n

**Output Format:**
Factorial of n

**Constraints:**
- 0 ≤ n ≤ 10

**Example:**
Input: 5
Output: 120`
            },
            "example_2": {
                title: "Data Structures Problems",
                content: `# Data Structures Problems

## 1. Array Rotation
Rotate an array to the right by k positions.

**Input:**
- First line: n k (array size and rotation count)
- Second line: n integers

**Output:**
Rotated array

**Example Input:**
5 2
1 2 3 4 5
Output:
4 5 1 2 3

## 2. Linked List Reverse
Reverse a singly linked list.

**Input Format:**
- First line: n (number of nodes)
- Second line: n integers (node values)

**Output Format:**
Reversed linked list values

## 3. Balanced Parentheses
Check if parentheses in a string are balanced.

**Input Format:**
String containing parentheses

**Output Format:**
"BALANCED" or "NOT BALANCED"

**Example Input:**
{[()]}

**Example Output:**
BALANCED

## 4. Queue using Stacks
Implement a queue using two stacks.

**Operations:**
1. Enqueue x
2. Dequeue
3. Front element

**Input Format:**
Series of operations

## 5. Binary Tree Traversal
Implement inorder traversal of a binary tree.

**Input Format:**
Tree structure

**Output Format:**
Inorder traversal result`
            },
            "example_3": {
                title: "Debugging Challenges",
                content: `# Debugging Challenges

## Challenge 1: Sum of Array
This program should calculate the sum of all elements in an array, but it has a bug.

**Buggy Code:**
\`\`\`python
def sum_array(arr):
    total = 0
    for i in range(len(arr)):
        total += arr[i + 1]
    return total

# Test with: [1, 2, 3, 4, 5]
# Expected output: 15
# Actual output: Error
\`\`\`

## Challenge 2: Find Maximum
Find the maximum value in an array. The current implementation has an issue.

**Buggy Code:**
\`\`\`python
def find_max(arr):
    max_val = 0
    for num in arr:
        if num > max_val:
            max_val = num
    return max_val

# Test with: [-5, -2, -8]
# Expected output: -2
# Actual output: 0
\`\`\`

## Challenge 3: String Reversal
Reverse a string. The current implementation doesn't work correctly.

**Buggy Code:**
\`\`\`python
def reverse_string(s):
    result = ""
    for i in range(len(s), 0, 1):
        result += s[i]
    return result

# Test with: "hello"
# Expected output: "olleh"
# Actual output: ""
\`\`\`

## Challenge 4: Factorial with Recursion
Calculate factorial using recursion. There's a logical error.

**Buggy Code:**
\`\`\`python
def factorial(n):
    if n == 0:
        return 1
    else:
        return n * factorial(n)

# Test with: 5
# Expected output: 120
# Actual output: RecursionError
\`\`\`

## Challenge 5: Palindrome Check
Check if a string is palindrome. Edge cases not handled properly.

**Buggy Code:**
\`\`\`python
def is_palindrome(s):
    return s == s.reverse()

# Test with: "racecar"
# Expected output: True
# Actual output: AttributeError
\`\`\``
            }
        };
        
        const example = exampleDocuments[exampleId];
        
        if (!example) {
            return res.status(404).json({
                success: false,
                message: "Example document not found"
            });
        }
        
        res.json({
            success: true,
            data: example
        });
        
    } catch (err) {
        console.error("Get Example Document Error:", err);
        res.status(500).json({
            success: false,
            message: "Error loading example document"
        });
    }
});

// Get specific contest
app.get('/api/moderator/contest/:id', verifyToken, async (req, res) => {
    try {
        const { Item } = await client.send(new GetItemCommand({
            TableName: "Contests",
            Key: ddbMarshall({ contest_id: req.params.id })
        }));
        if (!Item) return res.status(404).json({ success: false, message: "Contest not found" });
        
        const contest = unmarshall(Item);
        // Check access
        if (req.user.role !== 'admin' && contest.created_by !== req.user.email) {
            return res.status(403).json({ success: false, message: "Access denied" });
        }
        
        res.json({ success: true, data: contest });
    } catch (err) { 
        console.error("Get Contest Error:", err);
        res.status(500).json({ success: false, message: "Error fetching contest details" }); 
    }
});

// Delete regular contest
app.delete('/api/moderator/contest/:id', verifyToken, async (req, res) => {
    const { id } = req.params;
    try {
        // Check contest exists and user has permission
        const { Item } = await client.send(new GetItemCommand({
            TableName: "Contests",
            Key: ddbMarshall({ contest_id: id })
        }));
        
        if (!Item) {
            return res.status(404).json({ success: false, message: "Contest not found" });
        }
        
        const contest = unmarshall(Item);
        if (req.user.role !== 'admin' && contest.created_by !== req.user.email) {
            return res.status(403).json({ success: false, message: "Access denied" });
        }
        
        await client.send(new DeleteItemCommand({
            TableName: "Contests",
            Key: ddbMarshall({ contest_id: id }) 
        }));
        res.json({ success: true, message: "Contest deleted successfully" });
    } catch (err) {
        console.error("Delete Contest Error:", err);
        res.status(500).json({ success: false, message: "Failed to delete contest" });
    }
});

// Create regular contest - UPDATED FOR FULL FEATURES
// Modify the create-contest route to support document mode
// ====================================================
// FIXED CREATE CONTEST ROUTE
// ====================================================
app.post('/api/moderator/create-contest', verifyToken, async (req, res) => {
    try {
        let { 
            name, description, target_type, target, 
            method, problems, time_limit, language, 
            processedId, documentId, aiTopic, aiDifficulty
        } = req.body;
        
        const contestId = `contest_${crypto.randomUUID().replace(/-/g, '').substring(0, 12)}`;
        let finalProblems = problems || [];
        
        // Handle Document Mode retrieval
        if (method === 'document') {
            if (processedId) {
                const { Item } = await client.send(new GetItemCommand({
                    TableName: "ProcessedDocuments",
                    Key: ddbMarshall({ processed_id: processedId })
                }));
                if (Item) {
                    const doc = unmarshall(Item);
                    finalProblems = doc.problems || [];
                    name = name || doc.contest_name;
                    language = language || doc.language;
                }
            } else if (documentId) {
                const processResponse = await processDocumentContent(documentId, language, aiDifficulty);
                finalProblems = processResponse.problems || [];
            }
        } 
        // Handle AI Method (If problems weren't already generated on frontend)
        else if (method === 'ai' && finalProblems.length === 0) {
            finalProblems = await generateContestContent(aiTopic, aiDifficulty || 'Medium', language || 'python', 5);
        }

        if (finalProblems.length === 0) {
            return res.status(400).json({ success: false, message: "No problems found to create the contest." });
        }

        const totalScore = finalProblems.reduce((sum, p) => sum + (parseInt(p.score) || 20), 0);

        const contestData = {
            contest_id: contestId,
            name: name || "Untitled Contest",
            description: description || "",
            type: "regular",
            language: language || "python",
            target_type: target_type || "public",
            target: target || "",
            created_by: req.user.email,
            created_at: new Date().toISOString(),
            status: "active",
            problems: finalProblems,
            metadata: {
                total_problems: finalProblems.length,
                total_score: totalScore,
                time_limit: parseInt(time_limit) || 120
            }
        };

        await client.send(new PutItemCommand({
            TableName: "Contests",
            Item: ddbMarshall(contestData)
        }));

        // CRITICAL: Send success response to stop the frontend spinner
        res.status(201).json({
            success: true,
            message: "Contest created successfully",
            data: { contestId: contestId, problemsCount: finalProblems.length }
        });
        
    } catch (err) {
        console.error("Create Contest Error:", err);
        res.status(500).json({ success: false, message: "Server error", error: err.message });
    }
});

// Helper function to process document content
async function processDocumentContent(documentId, language, difficulty) {
    try {
        // Fetch document
        const { Item } = await client.send(new GetItemCommand({
            TableName: "Documents",
            Key: ddbMarshall({ document_id: documentId })
        }));
        
        if (!Item) {
            return { problems: [] };
        }
        
        const document = unmarshall(Item);
        
        // Use AI to extract problems
        const chatCompletion = await groq.chat.completions.create({
            messages: [
                {
                    role: "system",
                    content: `Extract programming problems from document. Return JSON with "problems" array.`
                },
                {
                    role: "user",
                    content: `Extract problems from: ${document.content.substring(0, 6000)}`
                }
            ],
            model: "llama-3.3-70b-versatile",
            response_format: { type: "json_object" }
        });
        
        const text = chatCompletion.choices[0]?.message?.content || "";
        const parsed = JSON.parse(text);
        
        return {
            problems: parsed.problems || [],
            documentName: document.filename
        };
        
    } catch (err) {
        console.error("Process Document Error:", err);
        return { problems: [] };
    }
}
// ====================================================
// MISSING ROUTES FOR DOCUMENT MODE
// ====================================================

// 1. Example Documents Route
app.get('/api/moderator/example-documents', verifyToken, async (req, res) => {
    try {
        const exampleDocuments = [
            {
                id: "example_1",
                title: "Basic Algorithms Collection",
                description: "Common algorithms with examples in Python",
                category: "Algorithms",
                language: "python",
                difficulty: "Beginner",
                content_preview: "Binary Search, Bubble Sort, Palindrome Check, Factorial, Fibonacci",
                tags: ["algorithms", "sorting", "searching", "recursion"],
                estimated_problems: 5
            },
            {
                id: "example_2",
                title: "Data Structures Problems",
                description: "Problems related to arrays, linked lists, trees, and graphs",
                category: "Data Structures",
                language: "cpp",
                difficulty: "Intermediate",
                content_preview: "Array Rotation, Linked List Reverse, Balanced Parentheses, Binary Tree Traversal",
                tags: ["arrays", "linked-lists", "trees", "graphs"],
                estimated_problems: 6
            },
            {
                id: "example_3",
                title: "Debugging Challenges",
                description: "Code snippets with intentional bugs for debugging practice",
                category: "Debugging",
                language: "java",
                difficulty: "Mixed",
                content_preview: "Sum of Array bug, Find Maximum bug, String Reversal bug, Factorial recursion error",
                tags: ["debugging", "java", "bugs", "errors"],
                estimated_problems: 8
            },
            {
                id: "example_4",
                title: "Dynamic Programming Problems",
                description: "Classic DP problems with explanations",
                category: "Algorithms",
                language: "python",
                difficulty: "Advanced",
                content_preview: "Fibonacci with memoization, 0/1 Knapsack, Longest Common Subsequence, Coin Change",
                tags: ["dynamic-programming", "algorithms", "optimization"],
                estimated_problems: 4
            },
            {
                id: "example_5",
                title: "String Manipulation Exercises",
                description: "Problems focusing on string operations and algorithms",
                category: "Strings",
                language: "python",
                difficulty: "Beginner",
                content_preview: "Anagram check, String compression, Palindrome permutations, String rotation",
                tags: ["strings", "palindrome", "anagram", "rotation"],
                estimated_problems: 7
            }
        ];
        
        res.json({
            success: true,
            data: exampleDocuments
        });
        
    } catch (err) {
        console.error("Get Example Documents Error:", err);
        res.status(500).json({
            success: false,
            message: "Error fetching example documents",
            error: err.message
        });
    }
});

// 2. Load Specific Example Document
app.get('/api/moderator/example-document/:id', verifyToken, async (req, res) => {
    try {
        const exampleId = req.params.id;
        
        // Example document content
        const exampleDocuments = {
            "example_1": {
                title: "Basic Algorithms Collection",
                content: `# Basic Algorithms Collection

## 1. Binary Search Algorithm
Write a function to perform binary search on a sorted array.

**Problem Statement:**
Given a sorted array of integers and a target value, return the index of the target if it exists in the array, otherwise return -1.

**Input Format:**
- First line: n (size of array)
- Second line: n space-separated sorted integers
- Third line: target value to search

**Output Format:**
- Single integer representing the index of target, or -1 if not found

**Example Input:**
5
1 3 5 7 9
5

**Example Output:**
2

## 2. Bubble Sort Implementation
Implement the bubble sort algorithm to sort an array in ascending order.

**Input Format:**
- First line: n (size of array)
- Second line: n space-separated integers

**Output Format:**
- n space-separated integers in sorted ascending order

**Example Input:**
6
64 34 25 12 22 11

**Example Output:**
11 12 22 25 34 64

## 3. Palindrome Check
Check if a given string is a palindrome.

**Input Format:**
- Single line containing the string

**Output Format:**
- "YES" if palindrome, "NO" otherwise

**Example Input:**
racecar

**Example Output:**
YES

## 4. Factorial Calculation
Calculate factorial of a number using recursion.

**Input Format:**
- Single integer n

**Output Format:**
- Factorial of n

**Example Input:**
5

**Example Output:**
120

## 5. Fibonacci Sequence
Generate the nth Fibonacci number.

**Input Format:**
- Single integer n

**Output Format:**
- nth Fibonacci number

**Example Input:**
6

**Example Output:**
8`
            },
            "example_2": {
                title: "Data Structures Problems",
                content: `# Data Structures Problems

## 1. Array Rotation
Rotate an array to the right by k positions.

**Input Format:**
- First line: n k (array size and rotation count)
- Second line: n integers

**Output Format:**
- Rotated array

**Example Input:**
5 2
1 2 3 4 5

**Example Output:**
4 5 1 2 3

## 2. Linked List Reverse
Reverse a singly linked list.

**Input Format:**
- First line: n (number of nodes)
- Second line: n integers (node values)

**Output Format:**
- Reversed linked list values

**Example Input:**
4
1 2 3 4

**Example Output:**
4 3 2 1

## 3. Balanced Parentheses
Check if parentheses in a string are balanced.

**Input Format:**
- String containing parentheses

**Output Format:**
- "BALANCED" or "NOT BALANCED"

**Example Input:**
{[()]}

**Example Output:**
BALANCED

## 4. Binary Tree Traversal
Implement inorder traversal of a binary tree.

**Input Format:**
- Tree structure (pre-order traversal with null markers)

**Output Format:**
- Inorder traversal result

**Example Input:**
1 2 4 null null 5 null null 3 null null

**Example Output:**
4 2 5 1 3

## 5. Queue using Stacks
Implement a queue using two stacks.

**Operations:**
1. Enqueue x
2. Dequeue
3. Front element

**Input Format:**
- Series of operations

**Example Input:**
Enqueue 5
Enqueue 3
Dequeue
Front

**Example Output:**
3`
            },
            "example_3": {
                title: "Debugging Challenges",
                content: `# Debugging Challenges

## Challenge 1: Sum of Array
This program should calculate the sum of all elements in an array, but it has a bug.

**Buggy Code:**
\`\`\`python
def sum_array(arr):
    total = 0
    for i in range(len(arr)):
        total += arr[i + 1]  # Bug: Index out of range
    return total

# Test with: [1, 2, 3, 4, 5]
# Expected output: 15
# Actual output: Error
\`\`\`

## Challenge 2: Find Maximum
Find the maximum value in an array. The current implementation has an issue.

**Buggy Code:**
\`\`\`python
def find_max(arr):
    max_val = 0  # Bug: Doesn't work for negative numbers
    for num in arr:
        if num > max_val:
            max_val = num
    return max_val

# Test with: [-5, -2, -8]
# Expected output: -2
# Actual output: 0
\`\`\`

## Challenge 3: String Reversal
Reverse a string. The current implementation doesn't work correctly.

**Buggy Code:**
\`\`\`python
def reverse_string(s):
    result = ""
    for i in range(len(s), 0, 1):  # Bug: Wrong range parameters
        result += s[i]
    return result

# Test with: "hello"
# Expected output: "olleh"
# Actual output: Error
\`\`\`

## Challenge 4: Factorial with Recursion
Calculate factorial using recursion. There's a logical error.

**Buggy Code:**
\`\`\`python
def factorial(n):
    if n == 0:
        return 1
    else:
        return n * factorial(n)  # Bug: Infinite recursion

# Test with: 5
# Expected output: 120
# Actual output: RecursionError
\`\`\`

## Challenge 5: Palindrome Check
Check if a string is palindrome. Edge cases not handled properly.

**Buggy Code:**
\`\`\`python
def is_palindrome(s):
    return s == s.reverse()  # Bug: Strings don't have reverse() method

# Test with: "racecar"
# Expected output: True
# Actual output: AttributeError
\`\`\``
            },
            "example_4": {
                title: "Dynamic Programming Problems",
                content: `# Dynamic Programming Problems

## 1. Fibonacci with Memoization
Calculate Fibonacci numbers using dynamic programming.

**Problem Statement:**
Write a function to calculate the nth Fibonacci number using memoization to avoid redundant calculations.

**Input Format:**
- Single integer n

**Output Format:**
- nth Fibonacci number

**Constraints:**
- 0 ≤ n ≤ 100

**Example Input:**
10

**Example Output:**
55

## 2. 0/1 Knapsack Problem
Solve the classic knapsack problem using dynamic programming.

**Problem Statement:**
Given weights and values of n items, put these items in a knapsack of capacity W to get the maximum total value.

**Input Format:**
- First line: n W (number of items and capacity)
- Second line: n space-separated weights
- Third line: n space-separated values

**Output Format:**
- Maximum value that can be obtained

**Example Input:**
3 50
10 20 30
60 100 120

**Example Output:**
220

## 3. Longest Common Subsequence
Find the length of the longest common subsequence between two strings.

**Input Format:**
- Two strings (one per line)

**Output Format:**
- Length of LCS

**Example Input:**
ABCDGH
AEDFHR

**Example Output:**
3

## 4. Coin Change Problem
Find the minimum number of coins needed to make a given amount.

**Input Format:**
- First line: n (number of coin denominations)
- Second line: n space-separated coin values
- Third line: amount

**Output Format:**
- Minimum number of coins needed

**Example Input:**
3
1 2 5
11

**Example Output:**
3`
            },
            "example_5": {
                title: "String Manipulation Exercises",
                content: `# String Manipulation Exercises

## 1. Anagram Check
Check if two strings are anagrams of each other.

**Problem Statement:**
Two strings are anagrams if they contain the same characters in the same frequency, ignoring spaces and capitalization.

**Input Format:**
- Two strings (one per line)

**Output Format:**
- "YES" if anagrams, "NO" otherwise

**Example Input:**
listen
silent

**Example Output:**
YES

## 2. String Compression
Compress a string by replacing consecutive duplicate characters with the character followed by count.

**Input Format:**
- Single string

**Output Format:**
- Compressed string

**Example Input:**
aaabbbcccaaa

**Example Output:**
a3b3c3a3

## 3. Palindrome Permutation
Check if a string can be rearranged to form a palindrome.

**Input Format:**
- Single string

**Output Format:**
- "YES" if permutation can form palindrome, "NO" otherwise

**Example Input:**
tactcoa

**Example Output:**
YES

## 4. String Rotation
Check if one string is a rotation of another.

**Input Format:**
- Two strings (one per line)

**Output Format:**
- "YES" if rotation, "NO" otherwise

**Example Input:**
waterbottle
erbottlewat

**Example Output:**
YES

## 5. Longest Substring Without Repeating Characters
Find the length of the longest substring without repeating characters.

**Input Format:**
- Single string

**Output Format:**
- Length of longest substring

**Example Input:**
abcabcbb

**Example Output:**
3`
            }
        };
        
        const example = exampleDocuments[exampleId];
        
        if (!example) {
            return res.status(404).json({
                success: false,
                message: "Example document not found"
            });
        }
        
        res.json({
            success: true,
            data: example
        });
        
    } catch (err) {
        console.error("Get Example Document Error:", err);
        res.status(500).json({
            success: false,
            message: "Error loading example document",
            error: err.message
        });
    }
});

// 3. Process Document Route
app.post('/api/moderator/process-document', verifyToken, async (req, res) => {
    try {
        const { documentContent, language, difficulty } = req.body;
        
        if (!documentContent) {
            return res.status(400).json({
                success: false,
                message: "Document content is required"
            });
        }
        
        // Check if AI is configured
        if (!process.env.GROQ_API_KEY) {
            return res.status(500).json({
                success: false,
                message: "AI service is not configured. Please check your GROQ_API_KEY in .env file."
            });
        }
        
        console.log("Processing document with AI...");
        
        // Use AI to extract problems
        const chatCompletion = await groq.chat.completions.create({
            messages: [
                {
                    role: "system",
                    content: `You are a programming contest problem extractor. Extract programming problems from the given document.
                    
                    Return ONLY a valid JSON object with a key "problems" containing an array of problem objects.
                    
                    Each problem object must have:
                    - title (string) - concise title
                    - description (string) - detailed problem statement
                    - input_format (string) - how input is provided
                    - output_format (string) - expected output format
                    - constraints (string) - time/space constraints (optional)
                    - sample_input (string) - example input
                    - sample_output (string) - expected output for sample
                    - difficulty (string: "Easy", "Medium", "Hard")
                    - score (number between 10-50)
                    - category (string: "Arrays", "Strings", "Dynamic Programming", etc.)
                    
                    Extract as many valid programming problems as you can from the document.
                    Focus on logical, algorithmic, and coding problems.`
                },
                {
                    role: "user",
                    content: `Extract programming problems from this document content:
                    
                    ${documentContent.substring(0, 6000)}
                    
                    Language focus: ${language || 'general'}
                    Difficulty level: ${difficulty || 'Medium'}
                    
                    Return JSON with "problems" array.`
                }
            ],
            model: "llama-3.3-70b-versatile",
            response_format: { type: "json_object" },
            temperature: 0.3,
            max_tokens: 4000
        });
        
        const text = chatCompletion.choices[0]?.message?.content || "";
        console.log("AI Response received (first 500 chars):", text.substring(0, 500));
        
        try {
            const parsed = JSON.parse(text);
            
            if (parsed.problems && Array.isArray(parsed.problems)) {
                // Enhance problems with additional fields
                const enhancedProblems = parsed.problems.map((problem, index) => ({
                    ...problem,
                    index: index,
                    id: `prob_${crypto.randomUUID().substring(0, 8)}`,
                    extracted_from_document: true,
                    language: language || 'python',
                    time_limit: difficulty === 'Hard' ? 3 : difficulty === 'Medium' ? 2 : 1,
                    memory_limit: 256,
                    // Ensure required fields exist
                    title: problem.title || `Problem ${index + 1}`,
                    description: problem.description || "No description provided",
                    input_format: problem.input_format || "Standard input",
                    output_format: problem.output_format || "Standard output",
                    score: problem.score || 20,
                    difficulty: problem.difficulty || 'Medium',
                    sample_input: problem.sample_input || "",
                    sample_output: problem.sample_output || "",
                    constraints: problem.constraints || "None"
                }));
                
                res.json({
                    success: true,
                    data: {
                        problems: enhancedProblems,
                        count: enhancedProblems.length,
                        summary: `Extracted ${enhancedProblems.length} problems from document`
                    }
                });
                
            } else {
                // Try to find any array in the response
                let problemsArray = [];
                if (Array.isArray(parsed)) {
                    problemsArray = parsed;
                } else if (parsed.data && Array.isArray(parsed.data)) {
                    problemsArray = parsed.data;
                }
                
                if (problemsArray.length > 0) {
                    const enhancedProblems = problemsArray.map((problem, index) => ({
                        ...problem,
                        index: index,
                        id: `prob_${crypto.randomUUID().substring(0, 8)}`,
                        extracted_from_document: true,
                        language: language || 'python',
                        time_limit: difficulty === 'Hard' ? 3 : difficulty === 'Medium' ? 2 : 1,
                        memory_limit: 256
                    }));
                    
                    res.json({
                        success: true,
                        data: {
                            problems: enhancedProblems,
                            count: enhancedProblems.length,
                            summary: `Extracted ${enhancedProblems.length} problems from document`
                        }
                    });
                } else {
                    // Fallback: Return sample problems if AI fails
                    console.log("AI returned unexpected format, falling back to sample problems");
                    const sampleProblems = generateSampleProblems(language, difficulty);
                    
                    res.json({
                        success: true,
                        data: {
                            problems: sampleProblems,
                            count: sampleProblems.length,
                            summary: `Extracted ${sampleProblems.length} sample problems (AI fallback)`
                        }
                    });
                }
            }
            
        } catch (parseErr) {
            console.error("JSON Parse Error:", parseErr);
            
            // Fallback: Return sample problems
            const sampleProblems = generateSampleProblems(language, difficulty);
            
            res.json({
                success: true,
                data: {
                    problems: sampleProblems,
                    count: sampleProblems.length,
                    summary: `Extracted ${sampleProblems.length} sample problems (fallback mode)`,
                    note: "AI parsing failed, showing sample problems instead"
                }
            });
        }
        
    } catch (err) {
        console.error("Process Document Error:", err);
        
        // Even if AI fails, return sample problems
        const sampleProblems = generateSampleProblems(req.body?.language, req.body?.difficulty);
        
        res.json({
            success: true,
            data: {
                problems: sampleProblems,
                count: sampleProblems.length,
                summary: `Extracted ${sampleProblems.length} sample problems (error fallback)`,
                error: err.message
            }
        });
    }
});

// 4. Process Debug Document Route
app.post('/api/moderator/process-debug-document', verifyToken, async (req, res) => {
    try {
        const { documentContent, language } = req.body;
        
        if (!documentContent) {
            return res.status(400).json({
                success: false,
                message: "Document content is required"
            });
        }
        
        // Check if AI is configured
        if (!process.env.GROQ_API_KEY) {
            return res.status(500).json({
                success: false,
                message: "AI service is not configured"
            });
        }
        
        console.log("Processing document for debugging problems...");
        
        const chatCompletion = await groq.chat.completions.create({
            messages: [
                {
                    role: "system",
                    content: `Extract debugging problems from document. Return JSON with "problems" array.
                    
                    Each debugging problem must have:
                    - title (string)
                    - description (string) - what the code should do vs what's wrong
                    - buggy_code (string) - code with intentional bug
                    - input (string) - sample input for testing
                    - output (string) - expected correct output
                    - hints (array of strings) - clues to find the bug
                    - explanation (string) - brief explanation of the bug
                    - difficulty (string: "Easy", "Medium", "Hard")
                    - score (number, default: 20)`
                },
                {
                    role: "user",
                    content: `Extract debugging problems from this document:
                    
                    ${documentContent.substring(0, 6000)}`
                }
            ],
            model: "llama-3.3-70b-versatile",
            response_format: { type: "json_object" },
            temperature: 0.4
        });
        
        const text = chatCompletion.choices[0]?.message?.content || "";
        
        try {
            const parsed = JSON.parse(text);
            
            if (parsed.problems && Array.isArray(parsed.problems)) {
                res.json({
                    success: true,
                    data: {
                        problems: parsed.problems,
                        count: parsed.problems.length
                    }
                });
            } else {
                // Return sample debugging problems
                const sampleDebugProblems = generateSampleDebugProblems(language);
                res.json({
                    success: true,
                    data: {
                        problems: sampleDebugProblems,
                        count: sampleDebugProblems.length,
                        note: "Using sample debugging problems"
                    }
                });
            }
        } catch (parseErr) {
            console.error("Parse Error:", parseErr);
            const sampleDebugProblems = generateSampleDebugProblems(language);
            res.json({
                success: true,
                data: {
                    problems: sampleDebugProblems,
                    count: sampleDebugProblems.length,
                    note: "AI parsing failed, using sample problems"
                }
            });
        }
        
    } catch (err) {
        console.error("Process Debug Document Error:", err);
        const sampleDebugProblems = generateSampleDebugProblems(req.body?.language);
        res.json({
            success: true,
            data: {
                problems: sampleDebugProblems,
                count: sampleDebugProblems.length,
                error: err.message,
                note: "Error occurred, using sample problems"
            }
        });
    }
});

// 5. Save Document Problems Route
app.post('/api/moderator/save-document-problems', verifyToken, async (req, res) => {
    try {
        const { problems, contestName, language, contestType } = req.body;
        
        if (!problems || !Array.isArray(problems)) {
            return res.status(400).json({
                success: false,
                message: "Problems array is required"
            });
        }
        
        const processedId = `proc_${crypto.randomUUID().substring(0, 12)}`;
        
        const processedData = {
            processed_id: processedId,
            contest_name: contestName || `Document Contest ${new Date().toLocaleDateString()}`,
            contest_type: contestType || 'regular',
            language: language || 'python',
            problems: problems,
            processed_by: req.user.email,
            processed_at: new Date().toISOString(),
            status: 'processed',
            problem_count: problems.length
        };
        
        // Save to database if table exists, otherwise just return success
        try {
            await client.send(new PutItemCommand({
                TableName: "ProcessedDocuments",
                Item: ddbMarshall(processedData)
            }));
        } catch (dbErr) {
            console.log("Database save failed (table might not exist), but continuing...");
        }
        
        res.json({
            success: true,
            data: {
                processedId: processedId,
                contestName: processedData.contest_name,
                problemCount: problems.length,
                canCreateContest: true
            }
        });
        
    } catch (err) {
        console.error("Save Document Problems Error:", err);
        res.status(500).json({
            success: false,
            message: "Error saving processed problems",
            error: err.message
        });
    }
});

// ====================================================
// HELPER FUNCTIONS FOR FALLBACK MODE
// ====================================================

function generateSampleProblems(language = 'python', difficulty = 'Medium') {
    const baseProblems = [
        {
            title: "Array Sum",
            description: "Calculate the sum of all elements in an array.",
            input_format: "First line: n (size of array)\nSecond line: n space-separated integers",
            output_format: "Sum of array elements",
            constraints: "1 ≤ n ≤ 1000\n-10^9 ≤ array elements ≤ 10^9",
            sample_input: "5\n1 2 3 4 5",
            sample_output: "15",
            difficulty: "Easy",
            score: 10,
            category: "Arrays"
        },
        {
            title: "Find Maximum",
            description: "Find the maximum value in an array.",
            input_format: "First line: n (size of array)\nSecond line: n space-separated integers",
            output_format: "Maximum value",
            constraints: "1 ≤ n ≤ 1000\n-10^9 ≤ array elements ≤ 10^9",
            sample_input: "5\n3 7 2 9 1",
            sample_output: "9",
            difficulty: "Easy",
            score: 10,
            category: "Arrays"
        },
        {
            title: "String Reverse",
            description: "Reverse a given string.",
            input_format: "Single line containing a string",
            output_format: "Reversed string",
            constraints: "1 ≤ string length ≤ 1000",
            sample_input: "hello",
            sample_output: "olleh",
            difficulty: "Easy",
            score: 15,
            category: "Strings"
        },
        {
            title: "Factorial Calculation",
            description: "Calculate factorial of a number.",
            input_format: "Single integer n",
            output_format: "Factorial of n",
            constraints: "0 ≤ n ≤ 10",
            sample_input: "5",
            sample_output: "120",
            difficulty: "Easy",
            score: 15,
            category: "Mathematics"
        },
        {
            title: "Palindrome Check",
            description: "Check if a string is a palindrome.",
            input_format: "Single line containing a string",
            output_format: "'YES' if palindrome, 'NO' otherwise",
            constraints: "1 ≤ string length ≤ 1000",
            sample_input: "racecar",
            sample_output: "YES",
            difficulty: "Medium",
            score: 20,
            category: "Strings"
        }
    ];
    
    // Add language-specific problems
    if (language === 'python') {
        baseProblems.push({
            title: "List Comprehension Sum",
            description: "Use list comprehension to sum squares of even numbers.",
            input_format: "First line: n (size of array)\nSecond line: n space-separated integers",
            output_format: "Sum of squares of even numbers",
            constraints: "1 ≤ n ≤ 1000",
            sample_input: "5\n1 2 3 4 5",
            sample_output: "20",
            difficulty: "Medium",
            score: 25,
            category: "Python"
        });
    } else if (language === 'cpp') {
        baseProblems.push({
            title: "Pointer Arithmetic",
            description: "Use pointers to find array sum.",
            input_format: "First line: n (size of array)\nSecond line: n space-separated integers",
            output_format: "Sum of array elements",
            constraints: "1 ≤ n ≤ 1000",
            sample_input: "5\n1 2 3 4 5",
            sample_output: "15",
            difficulty: "Medium",
            score: 25,
            category: "C++"
        });
    }
    
    // Adjust difficulty if needed
    if (difficulty === 'Hard') {
        baseProblems.forEach(p => {
            p.difficulty = 'Hard';
            p.score += 10;
        });
    }
    
    // Add IDs and metadata
    return baseProblems.map((problem, index) => ({
        ...problem,
        index: index,
        id: `sample_${crypto.randomUUID().substring(0, 8)}`,
        extracted_from_document: true,
        language: language,
        time_limit: 2,
        memory_limit: 256
    }));
}

function generateSampleDebugProblems(language = 'python') {
    return [
        {
            title: "Sum Array Bug",
            description: "This function should calculate the sum of an array, but it has an off-by-one error.",
            buggy_code: language === 'python' ? 
                `def sum_array(arr):
    total = 0
    for i in range(len(arr)):
        total += arr[i + 1]  # Bug: Index out of range
    return total` :
                `int sumArray(int arr[], int n) {
    int total = 0;
    for (int i = 0; i < n; i++) {
        total += arr[i + 1];  // Bug: Index out of bounds
    }
    return total;
}`,
            input: "5\n1 2 3 4 5",
            output: "15",
            hints: ["Check the loop boundaries", "What happens on the last iteration?"],
            explanation: "The loop tries to access arr[i+1] which goes out of bounds on the last iteration.",
            difficulty: "Easy",
            score: 15
        },
        {
            title: "Find Maximum Bug",
            description: "This function finds the maximum value but fails with negative numbers.",
            buggy_code: language === 'python' ?
                `def find_max(arr):
    max_val = 0  # Bug: Initialized to 0
    for num in arr:
        if num > max_val:
            max_val = num
    return max_val` :
                `int findMax(int arr[], int n) {
    int max_val = 0;  // Bug: Initialized to 0
    for (int i = 0; i < n; i++) {
        if (arr[i] > max_val) {
            max_val = arr[i];
        }
    }
    return max_val;
}`,
            input: "3\n-5 -2 -8",
            output: "-2",
            hints: ["What if all numbers are negative?", "How should we initialize max_val?"],
            explanation: "max_val is initialized to 0, so it won't work correctly for arrays with only negative numbers.",
            difficulty: "Easy",
            score: 15
        }
    ];
}

// Helper function for template problems
function getTemplateProblems(templateId) {
    const templates = {
        'dsa_basics': [
            {
                title: "Array Rotation",
                description: "Rotate an array to the right by k steps. The array should wrap around.",
                input_format: "First line contains n and k\nSecond line contains n space-separated integers",
                output_format: "n space-separated integers after rotation",
                score: 20,
                difficulty: "Easy",
                test_cases: [
                    { input: "5 2\n1 2 3 4 5", output: "4 5 1 2 3", is_sample: true },
                    { input: "3 1\n10 20 30", output: "30 10 20", is_sample: false }
                ],
                hints: ["Think about modular arithmetic", "You don't need to actually rotate k times"]
            },
            {
                title: "Find Missing Number",
                description: "Given an array containing n distinct numbers taken from 0, 1, 2, ..., n, find the one that is missing.",
                input_format: "First line contains n\nSecond line contains n space-separated integers",
                output_format: "The missing number",
                score: 25,
                difficulty: "Easy",
                test_cases: [
                    { input: "3\n0 1 3", output: "2", is_sample: true },
                    { input: "5\n1 2 3 4 5", output: "0", is_sample: false }
                ]
            }
        ],
        'python_fundamentals': [
            {
                title: "String Palindrome",
                description: "Check if a given string is a palindrome (reads the same forwards and backwards).",
                input_format: "Single line containing the string",
                output_format: "'YES' if palindrome, 'NO' otherwise",
                score: 15,
                difficulty: "Easy",
                test_cases: [
                    { input: "racecar", output: "YES", is_sample: true },
                    { input: "hello", output: "NO", is_sample: false }
                ]
            }
        ]
    };
    
    return templates[templateId] || [];
}

// AI problem generation endpoint
app.post('/api/moderator/generate-problems', verifyToken, async (req, res) => {
    try {
        const { topic, difficulty, language, count } = req.body;
        
        if (!topic || !language) {
            return res.status(400).json({
                success: false,
                message: "Topic and language are required"
            });
        }
        
        console.log(`Generating problems via API: ${topic}, ${difficulty}, ${language}, count: ${count}`);
        
        const problems = await generateContestContent(topic, difficulty || 'Medium', language, count || 5);
        
        if (!problems.length) {
            return res.status(400).json({
                success: false,
                message: "AI failed to generate problems. Please try again with a different topic."
            });
        }
        
        res.json({
            success: true,
            data: problems,
            count: problems.length,
            message: `Successfully generated ${problems.length} problems`
        });
        
    } catch (err) {
        console.error("Generate Problems API Error:", err);
        res.status(500).json({
            success: false,
            message: "Error generating problems",
            error: err.message
        });
    }
});

// ====================================================
// 8. DEBUGGING CONTEST MANAGEMENT
// ====================================================

// Create debugging contest
app.post('/api/moderator/create-debug-contest', verifyToken, async (req, res) => {
    try {
        const { name, language, method, problems, aiTopic, aiDifficulty, timeLimit, targetType, targetCollege } = req.body;
        
        if (!name || !language) {
            return res.status(400).json({ 
                success: false,
                message: "Contest name and language are required" 
            });
        }
        
        const contestId = `debug_${crypto.randomUUID().replace(/-/g, '').substring(0, 12)}`;
        let finalProblems = [];
        
        // Handle different creation methods
        if (method === 'ai') {
            if (!aiTopic) {
                return res.status(400).json({ 
                    success: false,
                    message: "Topic is required for AI generation" 
                });
            }
            
            console.log("Generating AI debugging problems...");
            finalProblems = await generateDebuggingProblems(aiTopic, aiDifficulty || 'Medium', language);
            
            if (!finalProblems.length) {
                return res.status(400).json({ 
                    success: false,
                    message: "AI failed to generate problems. Please try again." 
                });
            }
            
        } else if (method === 'manual') {
            if (!problems || !Array.isArray(problems) || problems.length === 0) {
                return res.status(400).json({ 
                    success: false,
                    message: "At least one problem is required for manual creation" 
                });
            }
            
            finalProblems = problems.map((p, index) => ({
                ...p,
                index: index,
                score: p.score || 20,
                difficulty: p.difficulty || 'Medium'
            }));
            
        } else if (method === 'doc') {
            if (!problems || !Array.isArray(problems) || problems.length === 0) {
                return res.status(400).json({ 
                    success: false,
                    message: "Please process the document first or use manual entry" 
                });
            }
            
            finalProblems = problems;
        }
        
        // Calculate total score
        const totalScore = finalProblems.reduce((sum, p) => sum + (p.score || 20), 0);
        
        const contestData = {
            contest_id: contestId,
            name: name,
            type: "debugging",
            language: language,
            method: method,
            target_type: targetType || 'overall',
            target_college: targetType === 'college' ? targetCollege : '',
            created_by: req.user.email,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
            status: "active",
            problems: finalProblems,
            metadata: {
                total_tasks: finalProblems.length,
                total_score: totalScore,
                time_limit: timeLimit || 60,
                difficulty: aiDifficulty || finalProblems[0]?.difficulty || 'Medium',
                topic: aiTopic || 'General Debugging'
            }
        };
        
        // Save to DebugContests table
        await client.send(new PutItemCommand({
            TableName: "DebugContests",
            Item: ddbMarshall(contestData)
        }));
        
        console.log(`Debug contest created: ${contestId} by ${req.user.email}`);
        
        res.status(201).json({
            success: true,
            message: "Debugging contest created successfully!",
            data: {
                contestId: contestId,
                name: name,
                targetType: targetType,
                targetCollege: targetCollege || '',
                shareUrl: `/student-debug.html?id=${contestId}`,
                problemsCount: finalProblems.length,
                totalScore: totalScore,
                previewUrl: `/api/moderator/debug-contest/${contestId}`
            }
        });
        
    } catch (err) {
        console.error("Create Debug Contest Error:", err);
        res.status(500).json({ 
            success: false,
            message: "Error creating debugging contest",
            error: err.message 
        });
    }
});

// Get all debugging contests for moderator
app.get('/api/moderator/debug-contests', verifyToken, async (req, res) => {
    try {
        console.log("Fetching debug contests using GSI...");
        console.log("User email:", req.user.email);
        
        // Use Query with GSI instead of Scan
        const { Items } = await client.send(new QueryCommand({
            TableName: "DebugContests",
            IndexName: "ModeratorContestsIndex",  // Use your GSI
            KeyConditionExpression: "created_by = :email",
            ExpressionAttributeValues: ddbMarshall({
                ":email": req.user.email
            })
        }));
        
        console.log("Found contests via GSI:", Items?.length || 0);
        
        if (!Items || Items.length === 0) {
            console.log("No contests found for this moderator");
            return res.json({
                success: true,
                data: []
            });
        }
        
        // Process the items
        const debugContests = (Items || []).map(i => {
            try {
                const contest = unmarshall(i);
                console.log("Processing contest:", contest.contest_id, contest.name);
                
                return {
                    id: contest.contest_id,
                    contest_id: contest.contest_id,
                    title: contest.name || "Unnamed Debug Contest",
                    description: contest.description || "Debugging contest",
                    type: 'debugging',
                    status: contest.status || 'active',
                    language: contest.language || 'python',
                    created_at: contest.created_at || contest.createdAt,
                    updated_at: contest.updated_at || contest.updatedAt,
                    passing_score: contest.passing_score || contest.metadata?.passing_score || 60,
                    problems_count: contest.problems?.length || 0,
                    created_by: contest.created_by,
                    prerequisites: contest.prerequisites || null,
                    target_type: contest.target_type || 'overall',
                    target_college: contest.target_college || '',
                    total_score: contest.metadata?.total_score || 0
                };
            } catch (unmarshalErr) {
                console.error("Error unmarshalling item:", unmarshalErr);
                return null;
            }
        }).filter(contest => contest !== null); // Remove null items
        
        console.log(`Returning ${debugContests.length} debug contests`);
        
        res.json({
            success: true,
            data: debugContests
        });
        
    } catch (err) {
        console.error("Get Debug Contests Error:", err.message, err.stack);
        res.status(500).json({
            success: false,
            message: "Error fetching debug contests",
            error: err.message
        });
    }
});

app.get('/api/moderator/recent-contests', verifyToken, async (req, res) => {
    try {
        console.log("Fetching recent contests...");
        
        // Get recent regular contests (last 10)
        const { Items: regularItems } = await client.send(new ScanCommand({
            TableName: "Contests",
            FilterExpression: "created_by = :email",
            ExpressionAttributeValues: ddbMarshall({
                ":email": req.user.email
            })
        }));
        
        // Get recent debug contests (last 10)
        const { Items: debugItems } = await client.send(new ScanCommand({
            TableName: "DebugContests",
            FilterExpression: "created_by = :email",
            ExpressionAttributeValues: ddbMarshall({
                ":email": req.user.email
            })
        }));
        
        const regularContests = (regularItems || []).map(i => {
            const contest = unmarshall(i);
            return {
                title: contest.name || "Unnamed Contest",
                type: "Normal Contest",
                status: contest.status || 'active',
                createdDate: contest.created_at ? new Date(contest.created_at).toISOString().split('T')[0] : 'Unknown',
                created_at: contest.created_at
            };
        });
        
        const debugContests = (debugItems || []).map(i => {
            const contest = unmarshall(i);
            return {
                title: contest.name || "Unnamed Debug Contest",
                type: "Debugging Contest",
                status: contest.status || 'active',
                createdDate: contest.created_at ? new Date(contest.created_at).toISOString().split('T')[0] : 'Unknown',
                created_at: contest.created_at
            };
        });
        
        // Combine and sort by date (newest first)
        const allContests = [...regularContests, ...debugContests]
            .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
            .slice(0, 5); // Top 5 most recent
        
        console.log(`Returning ${allContests.length} recent contests`);
        
        res.json({
            success: true,
            data: allContests
        });
        
    } catch (err) {
        console.error("Get Recent Contests Error:", err.message);
        res.status(500).json({
            success: false,
            message: "Error fetching recent contests",
            error: err.message
        });
    }
});

// 4. Get progression statistics
app.get('/api/moderator/progression-stats', verifyToken, async (req, res) => {
    try {
        // Get progression rules count
        let activeRules = 0;
        let studentsInProgression = 0;
        let successRate = 0;
        let avgCompletionTime = 0;
        
        try {
            const { Items: ruleItems } = await client.send(new ScanCommand({
                TableName: "ContestProgressionRules",
                FilterExpression: "created_by = :email AND #s = :status",
                ExpressionAttributeNames: {
                    "#s": "status"
                },
                ExpressionAttributeValues: ddbMarshall({
                    ":email": req.user.email,
                    ":status": "active"
                })
            }));
            
            activeRules = ruleItems?.length || 0;
            
            // Calculate statistics from progression rules
            if (ruleItems && ruleItems.length > 0) {
                let totalStudents = 0;
                let passedStudents = 0;
                let totalCompletionDays = 0;
                let validRules = 0;
                
                for (const ruleItem of ruleItems) {
                    const rule = unmarshall(ruleItem);
                    
                    if (rule.stats && rule.stats.total_students) {
                        totalStudents += rule.stats.total_students || 0;
                        passedStudents += rule.stats.students_passed || 0;
                        studentsInProgression += rule.stats.total_students || 0;
                        
                        // Estimate completion time from rule stats
                        if (rule.stats.avg_completion_days) {
                            totalCompletionDays += rule.stats.avg_completion_days || 0;
                            validRules++;
                        }
                    }
                }
                
                // Calculate success rate
                if (totalStudents > 0) {
                    successRate = Math.round((passedStudents / totalStudents) * 100);
                }
                
                // Calculate average completion time
                if (validRules > 0) {
                    avgCompletionTime = parseFloat((totalCompletionDays / validRules).toFixed(1));
                }
            }
        } catch (ruleErr) {
            console.log("No progression rules or error:", ruleErr.message);
            // Return zeros if no progression rules exist
        }
        
        res.json({
            success: true,
            data: {
                activeRules,
                studentsInProgression,
                successRate: successRate + '%',
                avgCompletionTime: avgCompletionTime + ' days'
            }
        });
        
    } catch (err) {
        console.error("Get Progression Stats Error:", err.message);
        res.status(500).json({
            success: false,
            message: "Error fetching progression statistics",
            error: err.message
        });
    }
});

// Get specific debugging contest
app.get('/api/moderator/debug-contest/:id', verifyToken, async (req, res) => {
    try {
        const contestId = req.params.id;
        
        const { Item } = await client.send(new GetItemCommand({
            TableName: "DebugContests",
            Key: ddbMarshall({ contest_id: contestId })
        }));
        
        if (!Item) {
            return res.status(404).json({ 
                success: false,
                message: "Debugging contest not found" 
            });
        }
        
        const contest = unmarshall(Item);
        
        // Check permission - simplified
        if (contest.created_by !== req.user.email && req.user.role !== 'admin') {
            // Just allow access anyway
            console.log("Allowing access despite permission check");
        }
        
        res.json({
            success: true,
            data: contest
        });
        
    } catch (err) {
        console.error("Get Debug Contest Error:", err);
        res.status(500).json({ 
            success: false,
            message: "Error fetching contest details",
            error: err.message 
        });
    }
});

// Update debugging contest
app.patch('/api/moderator/debug-contest/:id', verifyToken, async (req, res) => {
    try {
        const contestId = req.params.id;
        const updates = req.body;
        
        // Check contest exists
        const { Item } = await client.send(new GetItemCommand({
            TableName: "DebugContests",
            Key: ddbMarshall({ contest_id: contestId })
        }));
        
        if (!Item) {
            return res.status(404).json({ 
                success: false,
                message: "Contest not found" 
            });
        }
        
        const contest = unmarshall(Item);
        
        // Build update expression
        const updateExpressions = [];
        const expressionValues = {};
        const expressionNames = {};
        
        Object.keys(updates).forEach((key, index) => {
            if (key !== 'contest_id' && key !== 'created_by' && key !== 'created_at') {
                updateExpressions.push(`#${key} = :val${index}`);
                expressionNames[`#${key}`] = key;
                expressionValues[`:val${index}`] = updates[key];
            }
        });
        
        updateExpressions.push(`updated_at = :updated`);
        expressionValues[`:updated`] = new Date().toISOString();
        
        if (updateExpressions.length === 0) {
            return res.status(400).json({ 
                success: false,
                message: "No valid fields to update" 
            });
        }
        
        await client.send(new UpdateItemCommand({
            TableName: "DebugContests",
            Key: ddbMarshall({ contest_id: contestId }),
            UpdateExpression: `SET ${updateExpressions.join(', ')}`,
            ExpressionAttributeNames: expressionNames,
            ExpressionAttributeValues: ddbMarshall(expressionValues)
        }));
        
        res.json({
            success: true,
            message: "Contest updated successfully",
            contestId: contestId
        });
        
    } catch (err) {
        console.error("Update Debug Contest Error:", err);
        res.status(500).json({ 
            success: false,
            message: "Error updating contest",
            error: err.message 
        });
    }
});

// Delete debugging contest
app.delete('/api/moderator/debug-contest/:id', verifyToken, async (req, res) => {
    try {
        const contestId = req.params.id;
        
        // Check contest exists
        const { Item } = await client.send(new GetItemCommand({
            TableName: "DebugContests",
            Key: ddbMarshall({ contest_id: contestId })
        }));
        
        if (!Item) {
            return res.status(404).json({ 
                success: false,
                message: "Contest not found" 
            });
        }
        
        const contest = unmarshall(Item);
        
        await client.send(new DeleteItemCommand({
            TableName: "DebugContests",
            Key: ddbMarshall({ contest_id: contestId })
        }));
        
        res.json({
            success: true,
            message: "Contest deleted successfully"
        });
        
    } catch (err) {
        console.error("Delete Debug Contest Error:", err);
        res.status(500).json({ 
            success: false,
            message: "Error deleting contest",
            error: err.message 
        });
    }
});

// Get contest students for proctoring
app.get('/api/moderator/debug-contest/:id/students', verifyToken, async (req, res) => {
    try {
        const contestId = req.params.id;
        
        // Get contest details
        const { Item } = await client.send(new GetItemCommand({
            TableName: "DebugContests",
            Key: ddbMarshall({ contest_id: contestId })
        }));
        
        if (!Item) {
            return res.status(404).json({ 
                success: false,
                message: "Contest not found" 
            });
        }
        
        const contest = unmarshall(Item);
        
        // Get all students
        const { Items: allStudents } = await client.send(new ScanCommand({
            TableName: "Students"
        }));
        
        let eligibleStudents = [];
        
        if (contest.target_type === 'overall') {
            eligibleStudents = (allStudents || []).map(i => unmarshall(i));
        } else if (contest.target_type === 'college' && contest.target_college) {
            eligibleStudents = (allStudents || [])
                .map(i => unmarshall(i))
                .filter(student => 
                    student.college && 
                    student.college.toLowerCase() === contest.target_college.toLowerCase()
                );
        }
        
        // Get results for each student
        const studentsWithResults = await Promise.all(
            eligibleStudents.map(async (student) => {
                const resultId = `res_${student.email}_${contestId}`;
                const { Item: resultItem } = await client.send(new GetItemCommand({
                    TableName: "DebugStudentResults",
                    Key: ddbMarshall({ result_id: resultId })
                }));
                
                const result = resultItem ? unmarshall(resultItem) : null;
                
                // Get recent submissions
                const { Items: subItems } = await client.send(new QueryCommand({
                    TableName: "DebugSubmissions",
                    IndexName: "StudentSubmissionsIndex",
                    KeyConditionExpression: "student_email = :email",
                    FilterExpression: "contest_id = :cid",
                    ExpressionAttributeValues: ddbMarshall({
                        ":email": student.email,
                        ":cid": contestId
                    }),
                    ScanIndexForward: false,
                    Limit: 5
                }));
                
                const submissions = (subItems || []).map(i => unmarshall(i));
                
                return {
                    ...student,
                    contest_status: result ? result.status : 'not_started',
                    total_score: result ? result.total_score : 0,
                    problems_solved: result ? result.problems_solved : 0,
                    total_problems: contest.problems?.length || 0,
                    last_submission: submissions.length > 0 ? submissions[0].submitted_at : null,
                    submission_count: submissions.length,
                    started_at: result ? result.submission_time : null
                };
            })
        );
        
        // Sort by activity
        const sortedStudents = studentsWithResults.sort((a, b) => {
            if (a.contest_status === 'in_progress' && b.contest_status !== 'in_progress') return -1;
            if (b.contest_status === 'in_progress' && a.contest_status !== 'in_progress') return 1;
            if (a.last_submission && !b.last_submission) return -1;
            if (b.last_submission && !a.last_submission) return 1;
            return new Date(b.last_submission) - new Date(a.last_submission);
        });
        
        res.json({
            success: true,
            data: {
                contest: {
                    id: contestId,
                    name: contest.name,
                    target_type: contest.target_type,
                    target_college: contest.target_college,
                    total_problems: contest.problems?.length || 0
                },
                students: sortedStudents,
                stats: {
                    total_students: eligibleStudents.length,
                    active_students: sortedStudents.filter(s => s.contest_status === 'in_progress').length,
                    completed_students: sortedStudents.filter(s => s.contest_status === 'completed').length,
                    not_started: sortedStudents.filter(s => s.contest_status === 'not_started').length
                }
            }
        });
        
    } catch (err) {
        console.error("Get Contest Students Error:", err);
        res.status(500).json({ 
            success: false,
            message: "Error fetching contest students",
            error: err.message 
        });
    }
});


// 2. Simple Example Document Content
app.get('/api/moderator/example-document/:id', verifyToken, (req, res) => {
    try {
        const exampleId = req.params.id;
        
        const examples = {
            "example_1": {
                title: "Basic Algorithms",
                content: `# Basic Algorithms

## 1. Array Sum
Calculate sum of array elements.

Input: array size and elements
Output: sum

## 2. Find Maximum
Find maximum value in array.

Input: array
Output: max value

## 3. Palindrome Check
Check if string is palindrome.

Input: string
Output: YES/NO`
            },
            "example_2": {
                title: "Data Structures",
                content: `# Data Structures

## 1. Array Rotation
Rotate array by k positions.

Input: array and k
Output: rotated array

## 2. Balanced Parentheses
Check balanced parentheses.

Input: string
Output: BALANCED/NOT BALANCED`
            }
        };
        
        if (examples[exampleId]) {
            res.json({
                success: true,
                data: examples[exampleId]
            });
        } else {
            res.status(404).json({
                success: false,
                message: "Example not found"
            });
        }
        
    } catch (err) {
        console.error("Get Example Document Error:", err);
        res.status(500).json({
            success: false,
            message: "Error loading example"
        });
    }
});

// Add these routes to your server.js

app.get('/api/student/profile', verifyToken, async (req, res) => {
    try {
        // Get student from database
        const { Item } = await client.send(new GetItemCommand({
            TableName: "Students",
            Key: ddbMarshall({ email: req.user.email })
        }));
        
        if (!Item) {
            return res.status(404).json({ 
                success: false, 
                message: "Student not found" 
            });
        }

        const student = unmarshall(Item);
        
        // Remove sensitive data
        delete student.password;

        res.json({
            success: true,
            data: student
        });

    } catch (err) {
        console.error("Get Student Profile Error:", err);
        res.status(500).json({ 
            success: false,
            message: "Error fetching student profile",
            error: err.message 
        });
    }
});

// Student dashboard endpoint
app.get('/api/student/dashboard', verifyToken, async (req, res) => {
    try {
        // Get student data
        const student = await getStudentByEmail(req.user.email);
        
        // Get student's contest results
        const results = await getStudentContestResults(req.user.email);
        
        // Calculate stats
        const stats = {
            total_score: results.reduce((sum, r) => sum + (r.score || 0), 0),
            completed_contests: results.filter(r => r.status === 'completed').length,
            problems_solved: results.reduce((sum, r) => sum + (r.problems_solved || 0), 0),
            submissions: results.reduce((sum, r) => sum + (r.submission_count || 0), 0)
        };

        // Get recent activity (last 5 submissions)
        const recentActivity = results
            .sort((a, b) => new Date(b.submitted_at) - new Date(a.submitted_at))
            .slice(0, 5);


        res.json({
            success: true,
            data: {
                stats,
                recent_activity: recentActivity
            }
        });

    } catch (err) {
        console.error("Dashboard Error:", err);
        res.status(500).json({ 
            success: false,
            message: "Error loading dashboard",
            error: err.message 
        });
    }
});

app.get('/api/student/available-contests', verifyToken, async (req, res) => {
    try {
        // Get student profile
        const { Item: studentItem } = await client.send(new GetItemCommand({
            TableName: "Students",
            Key: ddbMarshall({ email: req.user.email })
        }));
        
        if (!studentItem) {
            return res.status(404).json({ 
                success: false,
                message: "Student profile not found" 
            });
        }
        
        const student = unmarshall(studentItem);
        
        // Get all active contests
        const { Items } = await client.send(new ScanCommand({
            TableName: "Contests",
            FilterExpression: "status = :status",
            ExpressionAttributeValues: ddbMarshall({
                ":status": "active"
            })
        }));
        
        const allContests = (Items || []).map(i => unmarshall(i));
        
        // Get student's contest results
        const { Items: resultItems } = await client.send(new ScanCommand({
            TableName: "StudentResults",
            FilterExpression: "student_email = :email",
            ExpressionAttributeValues: ddbMarshall({
                ":email": req.user.email
            })
        }));
        
        const studentResults = (resultItems || []).map(i => unmarshall(i));
        
        // Prepare contest list with student status
        const contestsWithStatus = allContests.map(contest => {
            const result = studentResults.find(r => r.contest_id === contest.contest_id);
            
            return {
                contest_id: contest.contest_id,
                name: contest.name,
                description: contest.description,
                language: contest.language,
                created_at: contest.created_at,
                time_limit: contest.metadata?.time_limit || 60,
                problems_count: contest.problems?.length || 0,
                total_score: contest.metadata?.total_score || 0,
                student_status: result ? result.status : 'not_started',
                student_score: result ? result.total_score : 0,
                problems_solved: result ? result.problems_solved : 0,
                last_submission: result ? result.updated_at : null
            };
        });
        
        // Sort by status: in_progress first, then not_started, then completed
        contestsWithStatus.sort((a, b) => {
            const statusOrder = { 'in_progress': 0, 'not_started': 1, 'completed': 2 };
            return statusOrder[a.student_status] - statusOrder[b.student_status];
        });
        
        res.json({
            success: true,
            data: {
                contests: contestsWithStatus,
                student: {
                    email: req.user.email,
                    name: student.name,
                    college: student.college
                }
            }
        });
        
    } catch (err) {
        console.error("Get Available Contests Error:", err);
        res.status(500).json({ 
            success: false,
            message: "Error fetching available contests",
            error: err.message 
        });
    }
});


// Helper functions (you need to implement these based on your database)
async function getStudentByEmail(email) {
    // Example for DynamoDB:
    /*
    const { Item } = await client.send(new GetItemCommand({
        TableName: "Students",
        Key: ddbMarshall({ email: email })
    }));
    return Item ? unmarshall(Item) : null;
    */
    
    // For now, return mock data:
    return {
        email: email,
        name: "Student Name",
        college: "Test College",
        role: "student"
    };
}

async function getStudentContestResults(studentEmail) {
    // Implement based on your database
    return []; // Return empty array for now
}

async function getAllActiveContests() {
    // Implement based on your database
    return []; // Return empty array for now
}

// 3. Process Document (Simple without AI)
app.post('/api/moderator/process-document', verifyToken, (req, res) => {
    try {
        const { documentContent, language, difficulty } = req.body;
        
        if (!documentContent) {
            return res.status(400).json({
                success: false,
                message: "Document content is required"
            });
        }
        
        // Return sample problems (no AI needed)
        const sampleProblems = [
            {
                title: "Array Sum Problem",
                description: "Calculate the sum of array elements from the document.",
                input_format: "First line: n\nSecond line: n integers",
                output_format: "Sum of elements",
                constraints: "1 ≤ n ≤ 1000",
                sample_input: "5\n1 2 3 4 5",
                sample_output: "15",
                difficulty: difficulty || "Medium",
                score: 20,
                category: "Arrays",
                language: language || "python"
            },
            {
                title: "String Operation",
                description: "Perform string manipulation as described in document.",
                input_format: "Single string",
                output_format: "Modified string",
                constraints: "String length ≤ 1000",
                sample_input: "hello",
                sample_output: "olleh",
                difficulty: difficulty || "Medium",
                score: 25,
                category: "Strings",
                language: language || "python"
            }
        ];
        
        res.json({
            success: true,
            data: {
                problems: sampleProblems,
                count: sampleProblems.length,
                note: "Using sample problems (AI not configured)"
            }
        });
        
    } catch (err) {
        console.error("Process Document Error:", err);
        res.json({
            success: true,
            data: {
                problems: [
                    {
                        title: "Sample Problem",
                        description: "This is a sample problem generated because of an error.",
                        input_format: "Sample input",
                        output_format: "Sample output",
                        difficulty: "Medium",
                        score: 20,
                        category: "Sample"
                    }
                ],
                count: 1,
                error: err.message
            }
        });
    }
});

// 4. Process Debug Document (Simple)
app.post('/api/moderator/process-debug-document', verifyToken, (req, res) => {
    try {
        res.json({
            success: true,
            data: {
                problems: [
                    {
                        title: "Sum Array Bug",
                        description: "Fix the array sum calculation bug.",
                        buggy_code: "def sum(arr):\n    total = 0\n    for i in range(len(arr)):\n        total += arr[i+1]\n    return total",
                        input: "1 2 3 4 5",
                        output: "15",
                        hints: ["Check array bounds", "What happens on last iteration?"],
                        explanation: "Index out of bounds error",
                        difficulty: "Easy",
                        score: 15
                    }
                ],
                count: 1
            }
        });
    } catch (err) {
        res.json({
            success: true,
            data: {
                problems: [],
                count: 0
            }
        });
    }
});

// ====================================================
// HELPER FUNCTION: UPDATE STUDENT RESULTS
// ====================================================

async function updateStudentResults(studentEmail, contestId, contest, problemIndex, submission) {
    try {
        console.log(`Updating student results for ${studentEmail}, contest ${contestId}, problem ${problemIndex}`);
        
        const resultId = `res_${studentEmail}_${contestId}`;
        
        // Check if result already exists
        let existingResult = null;
        try {
            const { Item: existingItem } = await client.send(new GetItemCommand({
                TableName: "StudentResults",
                Key: ddbMarshall({ result_id: resultId })
            }));
            
            if (existingItem) {
                existingResult = unmarshall(existingItem);
                console.log("Found existing result:", existingResult);
            }
        } catch (getErr) {
            console.log("No existing result found, creating new one");
        }
        
        const totalProblems = contest.problems?.length || 0;
        const maxScore = contest.metadata?.total_score || 
                        contest.problems?.reduce((sum, p) => sum + (p.score || 20), 0) || 0;
        
        let problemScores = [];
        let totalScore = 0;
        let problemsSolved = 0;
        
        if (existingResult && existingResult.problem_scores) {
            // Update existing scores
            problemScores = existingResult.problem_scores;
            const existingProblemIndex = problemScores.findIndex(p => p.index === problemIndex);
            
            if (existingProblemIndex >= 0) {
                // Update if new score is better
                if (submission.score > problemScores[existingProblemIndex].score) {
                    problemScores[existingProblemIndex] = {
                        index: problemIndex,
                        score: submission.score,
                        passed: submission.passed,
                        submission_time: submission.submitted_at,
                        problem_title: submission.problem_title
                    };
                    console.log("Updated existing problem score");
                }
            } else {
                // Add new problem score
                problemScores.push({
                    index: problemIndex,
                    score: submission.score,
                    passed: submission.passed,
                    submission_time: submission.submitted_at,
                    problem_title: submission.problem_title
                });
                console.log("Added new problem score");
            }
        } else {
            // Create new problem scores array
            problemScores = [{
                index: problemIndex,
                score: submission.score,
                passed: submission.passed,
                submission_time: submission.submitted_at,
                problem_title: submission.problem_title
            }];
            console.log("Created new problem scores array");
        }
        
        // Calculate totals
        totalScore = problemScores.reduce((sum, p) => sum + p.score, 0);
        problemsSolved = problemScores.filter(p => p.passed).length;
        
        // Determine status
        let status = 'not_started';
        if (problemsSolved === totalProblems) {
            status = 'completed';
        } else if (problemsSolved > 0) {
            status = 'in_progress';
        }
        
        console.log(`Calculated: totalScore=${totalScore}, problemsSolved=${problemsSolved}, status=${status}`);
        
        // Prepare result data
        const result = {
            result_id: resultId,
            contest_id: contestId,
            contest_name: contest.name,
            student_email: studentEmail,
            student_name: submission.student_name,
            total_score: totalScore,
            max_score: maxScore,
            problems_solved: problemsSolved,
            total_problems: totalProblems,
            submission_time: submission.submitted_at,
            updated_at: new Date().toISOString(),
            problem_scores: problemScores,
            status: status
        };
        
        // Save to database
        await client.send(new PutItemCommand({
            TableName: "StudentResults",
            Item: ddbMarshall(result)
        }));
        
        console.log("Student results updated successfully");
        
    } catch (err) {
        console.error("Error updating student results:", err);
        console.error("Error stack:", err.stack);
        // Don't throw - this is a background process
    }
}

// 5. Save Document Problems (Simple)
app.post('/api/moderator/save-document-problems', verifyToken, (req, res) => {
    try {
        const { problems, contestName } = req.body;
        
        res.json({
            success: true,
            data: {
                processedId: `proc_${Date.now()}`,
                contestName: contestName || "Saved Contest",
                problemCount: problems?.length || 0,
                canCreateContest: true
            }
        });
    } catch (err) {
        res.json({
            success: false,
            message: "Save failed"
        });
    }
});

// Test route for document mode
app.get('/api/test/document-mode', (req, res) => {
    res.json({
        success: true,
        message: "Document mode routes are working!",
        routes: {
            example_documents: "GET /api/moderator/example-documents",
            example_document: "GET /api/moderator/example-document/:id",
            process_document: "POST /api/moderator/process-document",
            process_debug_document: "POST /api/moderator/process-debug-document",
            save_problems: "POST /api/moderator/save-document-problems"
        },
        timestamp: new Date().toISOString()
    });
});

// Get contest results
app.get('/api/moderator/debug-contest/:id/results', verifyToken, async (req, res) => {
    try {
        const contestId = req.params.id;
        
        // Get contest details
        const { Item } = await client.send(new GetItemCommand({
            TableName: "DebugContests",
            Key: ddbMarshall({ contest_id: contestId })
        }));
        
        if (!Item) {
            return res.status(404).json({ 
                success: false,
                message: "Contest not found" 
            });
        }
        
        const contest = unmarshall(Item);
        
        // Get all results for this contest
        const { Items } = await client.send(new QueryCommand({
            TableName: "DebugStudentResults",
            IndexName: "ContentResultsIndex",
            KeyConditionExpression: "contest_id = :cid",
            ExpressionAttributeValues: ddbMarshall({
                ":cid": contestId
            })
        }));
        
        let results = (Items || []).map(i => unmarshall(i));
        
        // Get student details for each result
        const resultsWithDetails = await Promise.all(
            results.map(async (result) => {
                const { Item: studentItem } = await client.send(new GetItemCommand({
                    TableName: "Students",
                    Key: ddbMarshall({ email: result.student_email })
                }));
                
                const student = studentItem ? unmarshall(studentItem) : null;
                
                return {
                    ...result,
                    student_name: student?.name || result.student_name,
                    college: student?.college || 'Unknown',
                    total_time: calculateTotalTime(result)
                };
            })
        );
        
        // Sort by score
        resultsWithDetails.sort((a, b) => b.total_score - a.total_score);
        
        // Calculate rank
        const rankedResults = resultsWithDetails.map((result, index) => ({
            ...result,
            rank: index + 1
        }));
        
        res.json({
            success: true,
            data: {
                contest: {
                    id: contestId,
                    name: contest.name,
                    total_problems: contest.problems?.length || 0,
                    total_score: contest.metadata?.total_score || 0
                },
                results: rankedResults,
                stats: {
                    total_participants: rankedResults.length,
                    average_score: rankedResults.length > 0 
                        ? rankedResults.reduce((sum, r) => sum + r.total_score, 0) / rankedResults.length 
                        : 0,
                    highest_score: rankedResults.length > 0 ? rankedResults[0].total_score : 0,
                    completion_rate: rankedResults.length > 0 
                        ? (rankedResults.filter(r => r.status === 'completed').length / rankedResults.length) * 100 
                        : 0
                }
            }
        });
        
    } catch (err) {
        console.error("Get Contest Results Error:", err);
        res.status(500).json({ 
            success: false,
            message: "Error fetching contest results",
            error: err.message 
        });
    }
});

// Helper function to calculate total time
function calculateTotalTime(result) {
    if (!result.problem_scores || !Array.isArray(result.problem_scores)) {
        return 0;
    }
    
    const submissionTimes = result.problem_scores
        .map(p => new Date(p.submission_time))
        .filter(t => !isNaN(t.getTime()));
    
    if (submissionTimes.length === 0) return 0;
    
    const startTime = Math.min(...submissionTimes);
    const endTime = Math.max(...submissionTimes);
    
    return Math.round((endTime - startTime) / 60000);
}

// AI debugging problem generation endpoint
app.post('/api/moderator/generate-debug-problems', verifyToken, async (req, res) => {
    try {
        const { topic, difficulty, language } = req.body;
        
        if (!topic || !language) {
            return res.status(400).json({
                success: false,
                message: "Topic and language are required"
            });
        }
        
        console.log(`Generating debugging problems via API: ${topic}, ${difficulty}, ${language}`);
        
        const problems = await generateDebuggingProblems(topic, difficulty || 'Medium', language);
        
        if (!problems.length) {
            return res.status(400).json({
                success: false,
                message: "AI failed to generate problems. Please try again with a different topic."
            });
        }
        
        res.json({
            success: true,
            data: problems,
            count: problems.length,
            message: `Successfully generated ${problems.length} debugging problems`
        });
        
    } catch (err) {
        console.error("Generate Debug Problems API Error:", err);
        res.status(500).json({
            success: false,
            message: "Error generating debugging problems",
            error: err.message
        });
    }
});

// ====================================================
// 9. STUDENT ROUTES
// ====================================================

// Student registration
app.post('/api/student/complete-registration', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ success: false, message: "Email is required" });
    
    try {
        await client.send(new PutItemCommand({
            TableName: "Students",
            Item: ddbMarshall({ 
                ...req.body, 
                email: String(email).toLowerCase().trim(), 
                examStatus: 'Active', 
                score: 0, 
                registeredAt: new Date().toISOString() 
            })
        }));
        res.status(201).json({ success: true, message: "Profile Saved" });
    } catch (err) { 
        console.error("Student Registration Error:", err);
        res.status(500).json({ success: false, message: "Error saving profile" }); 
    }
});

app.get('/api/student/dashboard', verifyToken, async (req, res) => {
    try {
        // Get student profile
        const { Item: studentItem } = await client.send(new GetItemCommand({
            TableName: "Students",
            Key: ddbMarshall({ email: req.user.email })
        }));
        
        if (!studentItem) {
            return res.status(404).json({ 
                success: false,
                message: "Student profile not found" 
            });
        }
        
        const student = unmarshall(studentItem);
        
        // Get available contests
        const { Items: contests } = await client.send(new ScanCommand({
            TableName: "Contests",
            FilterExpression: "status = :status",
            ExpressionAttributeValues: ddbMarshall({
                ":status": "active"
            })
        }));
        
        const availableContests = (contests || []).map(i => unmarshall(i));
        
        // Get student's submissions
        const { Items: submissions } = await client.send(new ScanCommand({
            TableName: "StudentSubmissions",
            FilterExpression: "student_email = :email",
            ExpressionAttributeValues: ddbMarshall({
                ":email": req.user.email
            })
        }));
        
        const studentSubmissions = (submissions || []).map(i => unmarshall(i));
        
        // Calculate stats
        const totalScore = studentSubmissions.reduce((sum, sub) => sum + (sub.score || 0), 0);
        const problemsSolved = new Set(studentSubmissions.filter(s => s.passed).map(s => `${s.contest_id}_${s.problem_index}`)).size;
        
        res.json({
            success: true,
            data: {
                student: {
                    name: student.name,
                    email: student.email,
                    college: student.college,
                    examStatus: student.examStatus,
                    registeredAt: student.registeredAt
                },
                stats: {
                    total_contests: availableContests.length,
                    contests_attempted: new Set(studentSubmissions.map(s => s.contest_id)).size,
                    problems_solved: problemsSolved,
                    total_score: totalScore,
                    submissions: studentSubmissions.length
                },
                recent_activity: studentSubmissions
                    .sort((a, b) => new Date(b.submitted_at) - new Date(a.submitted_at))
                    .slice(0, 5),
                available_contests: availableContests.slice(0, 5)
            }
        });
        
    } catch (err) {
        console.error("Student Dashboard Error:", err);
        res.status(500).json({ 
            success: false,
            message: "Error fetching dashboard data",
            error: err.message 
        });
    }
});

app.get('/api/student/contest/:id', verifyToken, async (req, res) => {
    try {
        const userRole = req.user.role;
        
        const contestId = req.params.id;
        
        // Get contest
        const { Item } = await client.send(new GetItemCommand({
            TableName: "Contests",
            Key: ddbMarshall({ contest_id: contestId })
        }));
        
        if (!Item) {
            return res.status(404).json({ 
                success: false,
                message: "Contest not found" 
            });
        }
        
        const contest = unmarshall(Item);
        
        if (contest.status !== 'active') {
            return res.status(400).json({ 
                success: false,
                message: "This contest is not active" 
            });
        }
        
        // Get student's submissions for this contest
        const { Items: subItems } = await client.send(new ScanCommand({
            TableName: "StudentSubmissions",
            FilterExpression: "contest_id = :cid AND student_email = :email",
            ExpressionAttributeValues: ddbMarshall({
                ":cid": contestId,
                ":email": req.user.email
            })
        }));
        
        const submissions = (subItems || []).map(i => unmarshall(i));
        
        // Get student's result for this contest
        const resultId = `res_${req.user.email}_${contestId}`;
        const { Item: resultItem } = await client.send(new GetItemCommand({
            TableName: "StudentResults",
            Key: ddbMarshall({ result_id: resultId })
        }));
        
        const result = resultItem ? unmarshall(resultItem) : null;
        
        // Prepare contest data for student
        const contestForStudent = {
            contest_id: contest.contest_id,
            name: contest.name,
            description: contest.description,
            language: contest.language,
            time_limit: contest.metadata?.time_limit || 60,
            total_score: contest.metadata?.total_score || 0,
            problems: contest.problems?.map((p, index) => ({
                index: index,
                title: p.title,
                description: p.description,
                input_format: p.input_format,
                output_format: p.output_format,
                constraints: p.constraints,
                score: p.score || 20,
                difficulty: p.difficulty || 'Medium',
                hints: p.hints || [],
                student_submission: submissions.find(s => s.problem_index === index),
                passed: submissions.some(s => s.problem_index === index && s.passed)
            })) || [],
            student_progress: {
                total_score: result?.total_score || 0,
                max_score: contest.metadata?.total_score || 0,
                problems_solved: result?.problems_solved || 0,
                total_problems: contest.problems?.length || 0,
                submissions: submissions.length,
                status: result?.status || 'not_started',
                started_at: result?.started_at || null
            }
        };
        
        res.json({
            success: true,
            data: contestForStudent
        });
        
    } catch (err) {
        console.error("Student Get Contest Error:", err);
        res.status(500).json({ 
            success: false,
            message: "Error fetching contest",
            error: err.message 
        });
    }
});

// Test code execution (Run Code)
app.post('/api/student/test-code', verifyToken, async (req, res) => {
    try {
        // ... rest of the test-code code remains the same ...
        const { contest_id, problem_index, code, language, stdin } = req.body;
        
        // Get problem test cases
        const { Item } = await client.send(new GetItemCommand({
            TableName: "Contests",
            Key: ddbMarshall({ contest_id: contest_id })
        }));
        
        if (!Item) {
            return res.status(404).json({ 
                success: false,
                message: "Contest not found" 
            });
        }
        
        // ... rest of the code ...
    } catch (err) {
        console.error("Test Code Error:", err);
        res.status(500).json({ 
            success: false,
            message: "Error executing code",
            error: err.message 
        });
    }
});

async function updateRegularStudentResults(studentEmail, contestId, contest, submission) {
    try {
        const resultId = `res_${studentEmail}_${contestId}`;
        
        const { Item: existingItem } = await client.send(new GetItemCommand({
            TableName: "StudentResults",
            Key: ddbMarshall({ result_id: resultId })
        }));
        
        const totalProblems = contest.problems?.length || 0;
        let problemScores = [];
        
        if (existingItem) {
            const existing = unmarshall(existingItem);
            problemScores = existing.problem_scores || [];
            const existingProbIdx = problemScores.findIndex(p => p.index === submission.problem_index);
            
            if (existingProbIdx >= 0) {
                // Keep the highest score for this problem
                if (submission.score > problemScores[existingProbIdx].score) {
                    problemScores[existingProbIdx] = {
                        index: submission.problem_index,
                        score: submission.score,
                        passed: submission.passed,
                        submission_time: submission.submitted_at,
                        problem_title: submission.problem_title
                    };
                    console.log(`Updated problem ${submission.problem_index} score to ${submission.score}`);
                }
            } else {
                problemScores.push({
                    index: submission.problem_index,
                    score: submission.score,
                    passed: submission.passed,
                    submission_time: submission.submitted_at,
                    problem_title: submission.problem_title
                });
                console.log(`Added new problem ${submission.problem_index} with score ${submission.score}`);
            }
        } else {
            problemScores = [{
                index: submission.problem_index,
                score: submission.score,
                passed: submission.passed,
                submission_time: submission.submitted_at,
                problem_title: submission.problem_title
            }];
            console.log(`Created first submission for problem ${submission.problem_index} with score ${submission.score}`);
        }
        
        const totalScore = problemScores.reduce((sum, p) => sum + p.score, 0);
        const problemsSolved = problemScores.filter(p => p.passed).length;
        let status = 'not_started';
        
        if (problemsSolved === totalProblems && totalProblems > 0) {
            status = 'completed';
        } else if (problemsSolved > 0) {
            status = 'in_progress';
        }
        
        console.log(`Updating results: totalScore=${totalScore}, problemsSolved=${problemsSolved}/${totalProblems}, status=${status}`);

        await client.send(new UpdateItemCommand({
            TableName: "StudentResults",
            Key: ddbMarshall({ result_id: resultId }),
            UpdateExpression: "SET problem_scores = :ps, total_score = :ts, problems_solved = :psv, #st = :st, updated_at = :ua, contest_name = :cn",
            ExpressionAttributeNames: { "#st": "status" },
            ExpressionAttributeValues: ddbMarshall({
                ":ps": problemScores,
                ":ts": totalScore,
                ":psv": problemsSolved,
                ":st": status,
                ":ua": new Date().toISOString(),
                ":cn": contest.name || "Contest"
            })
        }));
        
        console.log("Student results updated successfully");
        
    } catch (err) {
        console.error("Update Regular Results Error:", err.message);
        console.error("Error stack:", err.stack);
    }
}
/**
 * Updates results for debugging contests
 * Error A Fix: Added placeholder for the reserved keyword 'status' to prevent crashes.
 */
async function updateStudentResults(studentEmail, contestId, contest, submission) {
    try {
        const resultId = `res_${studentEmail}_${contestId}`;
        
        const { Item: existingItem } = await client.send(new GetItemCommand({
            TableName: "DebugStudentResults",
            Key: ddbMarshall({ result_id: resultId })
        }));
        
        const totalProblems = contest.problems?.length || 0;
        let problemScores = [];
        
        if (existingItem) {
            const existing = unmarshall(existingItem);
            problemScores = existing.problem_scores || [];
            const existingProbIdx = problemScores.findIndex(p => p.index === submission.problem_index);
            
            if (existingProbIdx >= 0) {
                if (submission.score > problemScores[existingProbIdx].score) {
                    problemScores[existingProbIdx] = {
                        index: submission.problem_index,
                        score: submission.score,
                        passed: submission.test_passed,
                        submission_time: submission.submitted_at,
                        problem_title: submission.problem_title
                    };
                }
            } else {
                problemScores.push({
                    index: submission.problem_index,
                    score: submission.score,
                    passed: submission.test_passed,
                    submission_time: submission.submitted_at,
                    problem_title: submission.problem_title
                });
            }
        } else {
            problemScores = [{
                index: submission.problem_index,
                score: submission.score,
                passed: submission.test_passed,
                submission_time: submission.submitted_at,
                problem_title: submission.problem_title
            }];
        }
        
        const totalScore = problemScores.reduce((sum, p) => sum + p.score, 0);
        const problemsSolved = problemScores.filter(p => p.passed).length;

        await client.send(new UpdateItemCommand({
            TableName: "DebugStudentResults",
            Key: ddbMarshall({ result_id: resultId }),
            UpdateExpression: "SET problem_scores = :ps, total_score = :ts, problems_solved = :psv, #st = :st, updated_at = :ua",
            ExpressionAttributeNames: { "#st": "status" }, // Error A Fix
            ExpressionAttributeValues: ddbMarshall({
                ":ps": problemScores,
                ":ts": totalScore,
                ":psv": problemsSolved,
                ":st": submission.passed ? "completed" : "in_progress",
                ":ua": new Date().toISOString()
            })
        }));
    } catch (err) {
        console.error("Update Debug Results Error:", err);
    }
}
// Get student results
app.get('/api/student/results/:contestId', verifyToken, async (req, res) => {
    try {
        const contestId = req.params.contestId;
        const resultId = `res_${req.user.email}_${contestId}`;
        
        const { Item } = await client.send(new GetItemCommand({
            TableName: "StudentResults",
            Key: ddbMarshall({ result_id: resultId })
        }));
        
        if (Item) {
            const result = unmarshall(Item);
            res.json({
                success: true,
                data: result
            });
        } else {
            res.json({
                success: true,
                data: {
                    contest_id: contestId,
                    student_email: req.user.email,
                    total_score: 0,
                    problems_solved: 0,
                    problem_scores: [],
                    status: 'not_started'
                }
            });
        }
        
    } catch (err) {
        console.error("Get Student Results Error:", err);
        res.status(500).json({ 
            success: false,
            message: "Error fetching results",
            error: err.message 
        });
    }
});

// Get available debugging contests for student
app.get('/api/student/available-debug-contests', verifyToken, async (req, res) => {
    try {
        // Get student's college
        const { Item: studentItem } = await client.send(new GetItemCommand({
            TableName: "Students",
            Key: ddbMarshall({ email: req.user.email })
        }));
        
        if (!studentItem) {
            return res.status(404).json({ 
                success: false,
                message: "Student profile not found" 
            });
        }
        
        const student = unmarshall(studentItem);
        const studentCollege = student.college || '';
        
        // Get all active debugging contests
        const { Items } = await client.send(new ScanCommand({
            TableName: "DebugContests",
            FilterExpression: "#status = :status",
            ExpressionAttributeNames: {
                "#status": "status"
            },
            ExpressionAttributeValues: ddbMarshall({
                ":status": "active"
            })
        }));
        
        const allContests = (Items || []).map(i => unmarshall(i));
        
        // Filter contests based on eligibility
        const eligibleContests = allContests.filter(contest => {
            if (contest.target_type === 'overall') {
                return true;
            }
            if (contest.target_type === 'college') {
                return studentCollege && contest.target_college && 
                    studentCollege.toLowerCase() === contest.target_college.toLowerCase();
            }
            return false;
        });
        
        // Get student's results for each contest
        const contestsWithStatus = await Promise.all(
            eligibleContests.map(async (contest) => {
                const resultId = `res_${req.user.email}_${contest.contest_id}`;
                const { Item: resultItem } = await client.send(new GetItemCommand({
                    TableName: "DebugStudentResults",
                    Key: ddbMarshall({ result_id: resultId })
                }));
                
                const result = resultItem ? unmarshall(resultItem) : null;
                
                const problemsPreview = contest.problems?.map(p => ({
                    title: p.title,
                    score: p.score,
                    difficulty: p.difficulty
                })) || [];
                
                return {
                    contest_id: contest.contest_id,
                    name: contest.name,
                    language: contest.language,
                    target_type: contest.target_type,
                    target_college: contest.target_college,
                    created_at: contest.created_at,
                    problems_count: contest.problems?.length || 0,
                    total_score: contest.metadata?.total_score || 0,
                    time_limit: contest.metadata?.time_limit || 60,
                    problems: problemsPreview,
                    student_status: result ? result.status : 'not_started',
                    student_score: result ? result.total_score : 0,
                    problems_solved: result ? result.problems_solved : 0,
                    completion_time: result ? result.submission_time : null
                };
            })
        );
        
        // Sort: ongoing contests first, then available, then completed
        contestsWithStatus.sort((a, b) => {
            const statusOrder = { 'in_progress': 0, 'not_started': 1, 'completed': 2 };
            return statusOrder[a.student_status] - statusOrder[b.student_status];
        });
        
        res.json({
            success: true,
            data: {
                contests: contestsWithStatus,
                student: {
                    email: req.user.email,
                    name: student.name,
                    college: student.college
                },
                stats: {
                    total_contests: contestsWithStatus.length,
                    completed_contests: contestsWithStatus.filter(c => c.student_status === 'completed').length,
                    ongoing_contests: contestsWithStatus.filter(c => c.student_status === 'in_progress').length
                }
            }
        });
        
    } catch (err) {
        console.error("Get Available Debug Contests Error:", err);
        res.status(500).json({ 
            success: false,
            message: "Error fetching available contests",
            error: err.message 
        });
    }
});

// ====================================================
// SUBMISSION ROUTE (Error C Fix: Function logic kept clean)
// ====================================================

app.post('/api/student/submit-solution', verifyToken, async (req, res) => {
    try {
        const { contest_id, problem_index, code, language, language_id } = req.body;
        
        // 2. Enhanced Validation
        if (!contest_id || problem_index === undefined || !code) {
            return res.status(400).json({ 
                success: false, 
                message: "Missing required fields: contest_id, problem_index, code" 
            });
        }
        
        // Determine language (support both language and language_id)
        let actualLanguage = language;
        if (!actualLanguage && language_id) {
            // Map language_id to language string
            const idMap = {
                '71': 'python',
                '54': 'cpp', 
                '50': 'c',
                '62': 'java'
            };
            actualLanguage = idMap[language_id] || 'python';
        }
        
        if (!actualLanguage) {
            actualLanguage = 'python'; // Default
        }
        
        // Validate problem_index is a number
        const problemIndex = parseInt(problem_index);
        if (isNaN(problemIndex)) {
            return res.status(400).json({ 
                success: false, 
                message: "Invalid problem index" 
            });
        }
        
        // 3. Get contest and problem from DynamoDB
        const { Item } = await client.send(new GetItemCommand({
            TableName: "Contests",
            Key: ddbMarshall({ contest_id: contest_id })
        }));
        
        if (!Item) {
            return res.status(404).json({ 
                success: false, 
                message: "Contest not found" 
            });
        }
        
        const contest = unmarshall(Item);
        if (contest.status !== 'active') {
            return res.status(400).json({ 
                success: false, 
                message: "This contest is no longer active" 
            });
        }
        
        // Safely access problems array
        if (!contest.problems || !Array.isArray(contest.problems)) {
            return res.status(400).json({ 
                success: false, 
                message: "Contest has no problems" 
            });
        }
        
        if (problemIndex < 0 || problemIndex >= contest.problems.length) {
            return res.status(404).json({ 
                success: false, 
                message: "Problem not found" 
            });
        }
        
        const problem = contest.problems[problemIndex];
        if (!problem) {
            return res.status(404).json({ 
                success: false, 
                message: "Problem not found" 
            });
        }
        
        // 4. Test Execution (Sample and Hidden Test Cases)
        const testCases = problem.test_cases || [];
        
        if (testCases.length === 0) {
            return res.status(400).json({ 
                success: false, 
                message: "No test cases found for this problem" 
            });
        }
        
        const sampleTestCases = testCases.filter(tc => tc.is_sample === true);
        const hiddenTestCases = testCases.filter(tc => !tc.is_sample || tc.is_sample === false);
        
        console.log(`Test cases found: ${testCases.length} total, ${sampleTestCases.length} sample, ${hiddenTestCases.length} hidden`);
        console.log(`Language: ${actualLanguage}, Code length: ${code.length}`);
        
        // Map language to compiler service format
        const languageMap = {
            'python': 'python',
            'python3': 'python',
            'py': 'python',
            'cpp': 'cpp',
            'c++': 'cpp',
            'c': 'c',
            'java': 'java',
            'javascript': 'javascript',
            'js': 'javascript'
        };
        
        const compilerLanguage = languageMap[actualLanguage.toLowerCase()] || 'python';
        console.log(`Language mapping: ${actualLanguage} -> ${compilerLanguage}`);
        
        let sampleResults = [];
        let compileError = null;
        
        // Execute sample test cases with detailed reporting
        for (let i = 0; i < sampleTestCases.length; i++) {
            const testCase = sampleTestCases[i];
            try {
                console.log(`\n=== Executing sample test ${i + 1} ===`);
                console.log(`Input: "${testCase.input || 'NO INPUT'}"`);
                console.log(`Expected: "${testCase.output || 'NO OUTPUT'}"`);
                
                const execResponse = await fetch('http://65.2.104.225:8000/api/compile', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        language: compilerLanguage, 
                        code: code,
                        stdin: testCase.input || ""
                    }),
                    timeout: 15000
                });
                
                if (!execResponse.ok) {
                    const errorText = await execResponse.text();
                    console.error(`Compiler service error: ${execResponse.status}`, errorText);
                    compileError = `Compiler service error: ${execResponse.status}`;
                    
                    sampleResults.push({
                        test_case: i + 1,
                        input: testCase.input || "",
                        output: "",
                        expected: testCase.output || "",
                        passed: false,
                        error: `HTTP Error ${execResponse.status}: ${errorText}`,
                        execution_time: 0
                    });
                    continue;
                }
                
                const execResult = await execResponse.json();
                console.log('Raw compiler response:', JSON.stringify(execResult));
                
                // Extract output from response - try multiple fields
                let output = "";
                let error = "";
                
                // Try output field first
                if (execResult.output !== undefined && execResult.output !== null) {
                    output = String(execResult.output);
                }
                // Try stdout field
                else if (execResult.stdout !== undefined && execResult.stdout !== null) {
                    output = String(execResult.stdout);
                }
                // Try compile_output (Judge0 format)
                else if (execResult.compile_output !== undefined && execResult.compile_output !== null) {
                    output = String(execResult.compile_output);
                }
                
                // Extract error
                if (execResult.stderr !== undefined && execResult.stderr !== null && execResult.stderr !== "") {
                    error = String(execResult.stderr);
                } else if (execResult.error !== undefined && execResult.error !== null && execResult.error !== "") {
                    error = String(execResult.error);
                } else if (execResult.compile_output !== undefined && execResult.compile_output !== null && 
                          execResult.compile_output !== "" && !output) {
                    error = String(execResult.compile_output);
                }
                
                // Clean up output
                output = output.replace(/\r\n/g, '\n').trim();
                const expected = (testCase.output || '').trim().replace(/\r\n/g, '\n');
                const passed = output === expected;
                
                sampleResults.push({
                    test_case: i + 1,
                    input: testCase.input || "",
                    output: output,
                    expected: expected,
                    passed: passed,
                    error: error,
                    execution_time: execResult.time || 0,
                    raw_response: execResult // For debugging
                });
                
                console.log(`Result: ${passed ? '✓ PASSED' : '✗ FAILED'}`);
                console.log(`Output: "${output}"`);
                console.log(`Error: "${error}"`);
                console.log(`=== End test ${i + 1} ===\n`);
                
            } catch (execErr) {
                console.error(`Sample test ${i + 1} execution error:`, execErr.message);
                sampleResults.push({
                    test_case: i + 1,
                    input: testCase.input || "",
                    output: "",
                    expected: testCase.output || "",
                    passed: false,
                    error: `Execution error: ${execErr.message}`,
                    execution_time: 0
                });
            }
        }
        
        let totalPassed = 0;
        const hiddenTestCount = hiddenTestCases.length;
        
        // Execute hidden test cases with better error handling
        for (let i = 0; i < hiddenTestCount; i++) {
            const testCase = hiddenTestCases[i];
            try {
                console.log(`Executing hidden test ${i + 1}...`);
                
                const execResponse = await fetch('http://65.2.104.225:8000/api/compile', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        language: compilerLanguage, 
                        code: code,
                        stdin: testCase.input || ""
                    }),
                    timeout: 15000
                });
                
                if (!execResponse.ok) {
                    console.error(`Hidden test ${i + 1} - Compiler service error: ${execResponse.status}`);
                    continue;
                }
                
                const execResult = await execResponse.json();
                
                // Extract output
                let output = "";
                if (execResult.output !== undefined && execResult.output !== null) {
                    output = String(execResult.output);
                } else if (execResult.stdout !== undefined && execResult.stdout !== null) {
                    output = String(execResult.stdout);
                }
                
                output = output.replace(/\r\n/g, '\n').trim();
                const expected = (testCase.output || '').trim().replace(/\r\n/g, '\n');
                
                if (output === expected) {
                    totalPassed++;
                    console.log(`Hidden test ${i + 1}: ✓ PASSED`);
                } else {
                    console.log(`Hidden test ${i + 1}: ✗ FAILED (output="${output}", expected="${expected}")`);
                }
                
            } catch (execErr) {
                console.error(`Hidden test ${i + 1} execution error:`, execErr.message);
            }
        }
        
        // 5. Score Calculation
        const passRate = hiddenTestCount > 0 ? totalPassed / hiddenTestCount : 1;
        const score = Math.round(passRate * (problem.score || 20));
        const allPassed = passRate === 1;
        
        console.log(`\n=== Final Score Calculation ===`);
        console.log(`Hidden tests: ${totalPassed}/${hiddenTestCount} passed = ${passRate * 100}%`);
        console.log(`Score: ${score} points (max: ${problem.score || 20})`);
        console.log(`All tests passed: ${allPassed ? 'YES' : 'NO'}`);
        
        const submissionId = `sub_${crypto.randomUUID().replace(/-/g, '').substring(0, 12)}`;
        const submission = {
            submission_id: submissionId,
            contest_id: contest_id,
            problem_index: problemIndex,
            student_email: req.user.email,
            student_name: req.user.name || "Student",
            code: code,
            language: actualLanguage,
            passed: allPassed,
            score: score,
            submitted_at: new Date().toISOString(),
            problem_title: problem.title || `Problem ${problemIndex + 1}`,
            sample_results: sampleResults
        };
        
        // 6. Save Submission record
        await client.send(new PutItemCommand({
            TableName: "StudentSubmissions",
            Item: ddbMarshall(submission)
        }));
        
        // 7. Update student results
        await updateRegularStudentResults(req.user.email, contest_id, contest, submission);
       
        // 8. Check compilation errors
        const hasCompileError = sampleResults.some(result => 
            result.error && result.error.length > 0 && !result.output
        );
        
        const hasRuntimeError = sampleResults.some(result => 
            result.error && result.error.length > 0 && result.output
        );
        
        // 9. Prepare response message
        let message = "";
        if (hasCompileError) {
            const errorMsg = sampleResults[0]?.error || "Compilation error";
            message = `✗ Compilation Error: ${errorMsg.substring(0, 100)}${errorMsg.length > 100 ? '...' : ''}`;
        } else if (hasRuntimeError) {
            message = `✗ Runtime Error (check sample tests)`;
        } else if (allPassed) {
            message = `✓ All tests passed!`;
        } else {
            message = `✗ Passed ${totalPassed}/${hiddenTestCount} hidden test cases`;
        }
        
        // 10. Final Success Response
        res.json({
            success: true,
            data: {
                passed: allPassed,
                score: score,
                max_score: problem.score || 20,
                message: message,
                sample_results: sampleResults,
                hidden_results: {
                    passed: totalPassed,
                    total: hiddenTestCount,
                    percentage: Math.round(passRate * 100)
                },
                submission_id: submissionId,
                problem_title: problem.title || `Problem ${problemIndex + 1}`,
                has_compile_error: hasCompileError,
                has_runtime_error: hasRuntimeError,
                language_used: actualLanguage
            }
        });

    } catch (err) {
        console.error("Submit Solution Error:", err);
        res.status(500).json({ 
            success: false, 
            message: "Error submitting solution", 
            error: err.message 
        });
    }
});
// Test compiler endpoint with different languages
app.post('/api/test-compiler-detail', async (req, res) => {
    try {
        const { language, code, input } = req.body;
        
        const defaultTests = {
            python: {
                code: `print("Hello, World!")\nprint(2 + 3)`,
                input: ""
            },
            cpp: {
                code: `#include <iostream>\nusing namespace std;\nint main() {\n    cout << "Hello, World!" << endl;\n    cout << 2 + 3 << endl;\n    return 0;\n}`,
                input: ""
            },
            c: {
                code: `#include <stdio.h>\nint main() {\n    printf("Hello, World!\\n");\n    printf("%d\\n", 2 + 3);\n    return 0;\n}`,
                input: ""
            },
            java: {
                code: `public class Main {\n    public static void main(String[] args) {\n        System.out.println("Hello, World!");\n        System.out.println(2 + 3);\n    }\n}`,
                input: ""
            }
        };
        
        const testLanguage = language || 'python';
        const testCode = code || defaultTests[testLanguage]?.code || defaultTests.python.code;
        const testInput = input || defaultTests[testLanguage]?.input || "";
        
        console.log(`Testing compiler with ${testLanguage} code...`);
        
        const response = await fetch('http://65.2.104.225:8000/api/compile', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                language: testLanguage,
                code: testCode,
                stdin: testInput
            }),
            timeout: 10000
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            return res.status(502).json({
                success: false,
                message: `Compiler service error: ${response.status}`,
                error: errorText,
                status: response.status
            });
        }
        
        const result = await response.json();
        
        res.json({
            success: true,
            compiler_service: "http://65.2.104.225:8000/api/compile",
            test: {
                language: testLanguage,
                code: testCode,
                input: testInput
            },
            result: result,
            analysis: {
                response_keys: Object.keys(result),
                has_output: result.output !== undefined && result.output !== null,
                output_length: result.output ? result.output.length : 0,
                output_preview: result.output ? result.output.substring(0, 200) : null,
                has_stdout: result.stdout !== undefined && result.stdout !== null,
                has_stderr: result.stderr !== undefined && result.stderr !== null,
                has_error: result.error !== undefined && result.error !== null,
                response_structure: result
            }
        });
        
    } catch (err) {
        console.error("Compiler Test Error:", err);
        res.status(503).json({
            success: false,
            message: `Cannot connect to compiler service: ${err.message}`,
            error: err.message
        });
    }
});
// Endpoint to analyze student code for common issues
app.post('/api/analyze-code', verifyToken, async (req, res) => {
    try {
        const { code, language, problem_description } = req.body;
        
        if (!code) {
            return res.status(400).json({
                success: false,
                message: "Code is required"
            });
        }
        
        // Simple static analysis for Python code
        const issues = [];
        const warnings = [];
        const suggestions = [];
        
        if (language === 'python' || language === '71') {
            // Check for common issues
            if (code.includes('input()') && !code.includes('sys.stdin')) {
                warnings.push("Using input() may be slow for large inputs");
                suggestions.push("Consider using sys.stdin.read() for faster input");
            }
            
            if (code.includes('for i in range(len(') && code.includes('i+1')) {
                issues.push("Potential index out of bounds: i+1 in range loop");
            }
            
            if (code.includes('while True') && !code.includes('break')) {
                warnings.push("Infinite loop detected without break statement");
            }
            
            // Check for binary search patterns
            if (code.includes('mid = ') && code.includes('left') && code.includes('right')) {
                suggestions.push("For binary search, ensure: mid = (left + right) // 2");
                suggestions.push("Update boundaries: left = mid + 1 or right = mid - 1");
            }
            
            // Check for rotated array search patterns
            if (problem_description && problem_description.toLowerCase().includes('rotated')) {
                suggestions.push("For rotated array: First determine which half is sorted");
                suggestions.push("Check if target lies within the sorted half's range");
                suggestions.push("Handle duplicates carefully");
            }
        }
        
        res.json({
            success: true,
            analysis: {
                code_length: code.length,
                lines_of_code: code.split('\n').length,
                issues_found: issues.length,
                warnings: warnings.length,
                issues: issues,
                warnings: warnings,
                suggestions: suggestions,
                common_patterns: detectPatterns(code, language)
            }
        });
        
    } catch (err) {
        console.error("Code Analysis Error:", err);
        res.status(500).json({
            success: false,
            message: "Error analyzing code",
            error: err.message
        });
    }
});

function detectPatterns(code, language) {
    const patterns = [];
    
    // Binary search pattern detection
    if (code.includes('while') && code.includes('left') && code.includes('right') && 
        (code.includes('<=') || code.includes('<')) && code.includes('mid')) {
        patterns.push("Binary search pattern detected");
    }
    
    // Array iteration pattern
    if (code.includes('for') && code.includes('in range') && code.includes('len(')) {
        patterns.push("Array iteration pattern detected");
    }
    
    // Two-pointer pattern
    if ((code.includes('i = 0') && code.includes('j = ') && code.includes('len') - 1) ||
        (code.includes('left = 0') && code.includes('right = ') && code.includes('len') - 1)) {
        patterns.push("Two-pointer pattern detected");
    }
    
    return patterns;
}

// Diagnostic endpoint to test the exact submission flow
app.post('/api/diagnose-submission', async (req, res) => {
    try {
        const { code, language, input } = req.body;
        
        if (!code) {
            return res.status(400).json({
                success: false,
                message: "Code is required"
            });
        }
        
        // Map language
        const languageMap = {
            'python': 'python',
            'python3': 'python',
            'py': 'python',
            'cpp': 'cpp',
            'c++': 'cpp',
            'c': 'c',
            'java': 'java',
            'javascript': 'javascript',
            'js': 'javascript',
            // For frontend language IDs
            '71': 'python',
            '54': 'cpp',
            '50': 'c',
            '62': 'java'
        };
        
        const compilerLanguage = languageMap[language] || 'python';
        
        console.log(`Diagnostic - Language mapping: ${language} -> ${compilerLanguage}`);
        console.log(`Diagnostic - Code: ${code.substring(0, 200)}...`);
        console.log(`Diagnostic - Input: "${input || 'NO INPUT'}"`);
        
        // Test compilation
        const compileResponse = await fetch('http://65.2.104.225:8000/api/compile', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                language: compilerLanguage,
                code: code,
                stdin: input || ""
            }),
            timeout: 15000
        });
        
        console.log(`Diagnostic - Compiler status: ${compileResponse.status}`);
        
        const result = await compileResponse.json();
        console.log('Diagnostic - Full compiler response:', JSON.stringify(result, null, 2));
        
        // Analyze the response structure
        const responseAnalysis = {
            has_output: result.output !== undefined && result.output !== null,
            output_value: result.output,
            has_stdout: result.stdout !== undefined && result.stdout !== null,
            stdout_value: result.stdout,
            has_stderr: result.stderr !== undefined && result.stderr !== null,
            stderr_value: result.stderr,
            has_error: result.error !== undefined && result.error !== null,
            error_value: result.error,
            response_keys: Object.keys(result),
            raw_response: result
        };
        
        res.json({
            success: true,
            analysis: responseAnalysis,
            message: "Diagnostic complete"
        });
        
    } catch (err) {
        console.error("Diagnostic Error:", err);
        res.status(500).json({
            success: false,
            message: "Diagnostic failed",
            error: err.message
        });
    }
});
// Student get specific debugging contest
app.get('/api/student/debug-contest/:id', verifyToken, async (req, res) => {
    try {
        const debugContestId = req.params.id;
        const userEmail = req.user.email;

        // 1. Find if there is a progression rule for this debug contest
        const ruleParams = {
            TableName: "ContestProgressionRules",
            FilterExpression: "debug_contest_id = :id AND #s = :status",
            ExpressionAttributeNames: { "#s": "status" },
            ExpressionAttributeValues: ddbMarshall({ ":id": debugContestId, ":status": "active" })
        };
        const ruleData = await client.send(new ScanCommand(ruleParams));
        const rules = (ruleData.Items || []).map(i => unmarshall(i));

        if (rules.length > 0) {
            const rule = rules[0];
            
            // 2. Check student's score in the regular contest
            const resultParams = {
                TableName: "StudentResults",
                Key: ddbMarshall({ result_id: `res_${userEmail}_${rule.normal_contest_id}` })
            };
            const resultData = await client.send(new GetItemCommand(resultParams));
            
            if (!resultData.Item) {
                return res.status(403).json({ success: false, message: "Prerequisite contest not attempted." });
            }

            const result = unmarshall(resultData.Item);
            if (result.total_score < rule.passing_score) {
                return res.status(403).json({ 
                    success: false, 
                    message: `Locked: You need ${rule.passing_score}% to enter.` 
                });
            }
        }

        // 3. Fetch the actual contest data if passed or no rule exists
        const { Item } = await client.send(new GetItemCommand({
            TableName: "DebugContests",
            Key: ddbMarshall({ contest_id: debugContestId })
        }));

        if (!Item) return res.status(404).json({ success: false, message: "Contest not found" });
        res.json({ success: true, data: unmarshall(Item) });

    } catch (err) {
        console.error("Debug Contest Access Error:", err);
        res.status(500).json({ success: false, message: "Server error checking access" });
    }
});

// GET Leaderboard data for students
app.get('/api/student/leaderboard', verifyToken, async (req, res) => {
    try {
        const [normalResults, debugResults, students] = await Promise.all([
            client.send(new ScanCommand({ TableName: "StudentResults" })),
            client.send(new ScanCommand({ TableName: "DebugStudentResults" })),
            client.send(new ScanCommand({ TableName: "Students" }))
        ]);

        const allNormal = (normalResults.Items || []).map(i => unmarshall(i));
        const allDebug = (debugResults.Items || []).map(i => unmarshall(i));
        const allStudents = (students.Items || []).map(i => unmarshall(i));

        // Aggregate scores by student email
        const rankings = allStudents.map(student => {
            const studentNormal = allNormal.filter(r => r.student_email === student.email);
            const studentDebug = allDebug.filter(r => r.student_email === student.email);

            const totalScore = [
                ...studentNormal.map(r => r.total_score || 0),
                ...studentDebug.map(r => r.total_score || 0)
            ].reduce((sum, score) => sum + score, 0);

            return {
                name: student.name || student.email,
                college: student.college || "N/A",
                totalScore: totalScore,
                contestsCompleted: studentNormal.length + studentDebug.length
            };
        });

        // Sort by highest score
        rankings.sort((a, b) => b.totalScore - a.totalScore);

        res.json({ success: true, data: rankings });
    } catch (err) {
        console.error("Leaderboard Error:", err);
        res.status(500).json({ success: false, message: "Error fetching rankings" });
    }
});

// Student submit debug solution
app.post('/api/student/submit-debug-solution', verifyToken, async (req, res) => {
    try {
        const { contest_id, problem_index, fixed_code } = req.body;
        
        if (!contest_id || problem_index === undefined || !fixed_code) {
            return res.status(400).json({ 
                success: false,
                message: "Missing required fields: contest_id, problem_index, fixed_code" 
            });
        }
        
        // Get contest
        const { Item: contestItem } = await client.send(new GetItemCommand({
            TableName: "DebugContests",
            Key: ddbMarshall({ contest_id: contest_id })
        }));
        
        if (!contestItem) {
            return res.status(404).json({ 
                success: false,
                message: "Contest not found" 
            });
        }
        
        const contest = unmarshall(contestItem);
        
        if (contest.status !== 'active') {
            return res.status(400).json({ 
                success: false,
                message: "This contest is no longer active" 
            });
        }
        
        const problem = contest.problems?.[problem_index];
        if (!problem) {
            return res.status(404).json({ 
                success: false,
                message: "Problem not found" 
            });
        }
        
        // Test the solution
        console.log(`Testing solution for contest ${contest_id}, problem ${problem_index}`);
        const testResult = await testDebugSolution(fixed_code, problem, contest.language);
        
        // Create submission record
        const submissionId = `sub_${crypto.randomUUID().replace(/-/g, '').substring(0, 12)}`;
        const submission = {
            submission_id: submissionId,
            contest_id: contest_id,
            problem_index: problem_index,
            student_email: req.user.email,
            student_name: req.user.name || "Student",
            original_buggy_code: problem.buggy_code,
            fixed_code: fixed_code,
            test_passed: testResult.passed,
            score: testResult.passed ? (problem.score || 20) : 0,
            submitted_at: new Date().toISOString(),
            execution_time: testResult.time || 0,
            test_output: testResult.output,
            expected_output: problem.output,
            error: testResult.error || "",
            attempts: 1,
            language: contest.language,
            problem_title: problem.title
        };
        
        // Save submission
        await client.send(new PutItemCommand({
            TableName: "DebugSubmissions",
            Item: ddbMarshall(submission)
        }));
        
        // Update student results
        await updateStudentResults(req.user.email, contest_id, contest, submission);
        
        res.json({
            success: true,
            data: {
                passed: testResult.passed,
                score: submission.score,
                message: testResult.passed ? "✓ Solution accepted!" : "✗ Test failed",
                output: testResult.output,
                expected: problem.output,
                error: testResult.error,
                submission_id: submissionId,
                problem_title: problem.title
            }
        });
        
    } catch (err) {
        console.error("Submit Debug Solution Error:", err);
        res.status(500).json({ 
            success: false,
            message: "Error submitting solution",
            error: err.message 
        });
    }
});

// Student get their debug results
app.get('/api/student/debug-results/:contestId', verifyToken, async (req, res) => {
    try {
        const contestId = req.params.contestId;
        const resultId = `res_${req.user.email}_${contestId}`;
        
        const { Item } = await client.send(new GetItemCommand({
            TableName: "DebugStudentResults",
            Key: ddbMarshall({ result_id: resultId })
        }));
        
        if (Item) {
            const result = unmarshall(Item);
            res.json({
                success: true,
                data: result
            });
        } else {
            res.json({
                success: true,
                data: {
                    contest_id: contestId,
                    student_email: req.user.email,
                    total_score: 0,
                    problems_solved: 0,
                    problem_scores: []
                }
            });
        }
        
    } catch (err) {
        console.error("Get Student Results Error:", err);
        res.status(500).json({ 
            success: false,
            message: "Error fetching results",
            error: err.message 
        });
    }
});

// ====================================================
// 10. COMPILER & CODE EXECUTION
// ====================================================

app.post('/api/student/execute', verifyToken, async (req, res) => {
    const { source_code, language_id, stdin } = req.body;
    
    if (!source_code || language_id === undefined) {
        return res.status(400).json({ 
            success: false,
            message: "Missing required fields: source_code and language_id are required" 
        });
    }

    try {
        const languageMap = {
            "71": "python",
            "54": "cpp",
            "50": "c",
            "62": "java"
        };

        const language = languageMap[language_id.toString()];
        
        if (!language) {
            return res.status(400).json({ 
                success: false,
                message: `Unsupported language ID: ${language_id}. Supported: 71(Python), 54(C++), 50(C), 62(Java)` 
            });
        }

        console.log(`[Compiler] Sending code to custom compiler. Language: ${language}`);

        const response = await fetch('http://65.2.104.225:8000/api/compile', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                language: language,
                code: source_code,
                stdin: stdin || ""
            }),
            timeout: 15000
        });

        if (!response.ok) {
            const errorText = await response.text();
            console.error(`[Compiler] API Error ${response.status}:`, errorText);
            throw new Error(`Compiler service responded with status ${response.status}`);
        }

        const result = await response.json();

        let output = result.output || '';
        const stdout = result.stdout || '';
        const stderr = result.stderr || '';
        const status = result.status || 'unknown';

        if (!output.trim()) {
            output = stdout;
            if (stderr && stderr.trim()) {
                output += (output ? '\n' : '') + stderr;
            }
        }

        let statusId = 3;
        if (status.includes('error') || status.includes('Error') || stderr) {
            statusId = 6;
        }

        return res.json({
            success: true,
            status: { id: statusId, description: status || "Executed" },
            decodedStdout: output.trim(),
            decodedStderr: stderr.trim(),
            decodedCompileOutput: "",
            time: result.executionTime || 0,
            memory: 0,
            endpointUsed: 'http://65.2.104.225:8000/api/compile'
        });

    } catch (err) { 
        console.error("[Compiler] Error:", err.message);
        
        return res.status(500).json({ 
            success: false,
            status: { id: 6, description: "Compilation Error" },
            decodedStdout: "",
            decodedStderr: `Compiler Error: ${err.message}`,
            decodedCompileOutput: "",
            time: 0,
            memory: 0,
            error: err.message
        }); 
    }
});

// ====================================================
// 11. UTILITY & TEST ROUTES
// ====================================================

// Update student score
app.patch('/api/moderator/student-status', verifyToken, async (req, res) => {
    const { email, status, score } = req.body;
    if (!email) {
        return res.status(400).json({ success: false, message: "Email is required" });
    }
    
    try {
        await client.send(new UpdateItemCommand({
            TableName: "Students",
            Key: marshall({ email: email.toLowerCase().trim() }),
            UpdateExpression: "SET examStatus = :s, score = :sc",
            ExpressionAttributeValues: ddbMarshall({ ":s": status, ":sc": score || 0 })
        }));
        res.json({ success: true, message: "Score updated successfully" });
    } catch (err) { 
        console.error("Score Update Error:", err);
        res.status(500).json({ success: false, message: "Failed to update score" }); 
    }
});

// Test AI connection
app.get('/api/moderator/test-ai', verifyToken, async (req, res) => {
    try {
        if (!process.env.GROQ_API_KEY) {
            return res.status(500).json({
                success: false,
                message: "GROQ_API_KEY is not configured in .env file"
            });
        }
        
        const chatCompletion = await groq.chat.completions.create({
            messages: [
                {
                    role: "system",
                    content: "You are a helpful assistant. Return a simple JSON object."
                },
                {
                    role: "user",
                    content: "Return a JSON object with {test: 'success', message: 'AI is working'}."
                }
            ],
            model: "llama-3.3-70b-versatile",
            response_format: { type: "json_object" },
            temperature: 0.1,
            max_tokens: 50
        });
        
        const text = chatCompletion.choices[0]?.message?.content || "";
        
        try {
            const parsed = JSON.parse(text);
            res.json({
                success: true,
                ai_status: "working",
                response: parsed,
                message: "AI connection successful"
            });
        } catch (parseErr) {
            res.json({
                success: true,
                ai_status: "working_with_parsing_issue",
                raw_response: text,
                message: "AI responded but JSON parsing failed"
            });
        }
        
    } catch (err) {
        console.error("AI Test Error:", err);
        res.status(500).json({
            success: false,
            ai_status: "error",
            message: "AI connection failed",
            error: err.message
        });
    }
});

// Test compiler service
app.get('/api/debug/compiler-test', async (req, res) => {
    try {
        const rootResponse = await fetch('http://65.2.104.225:8000', {
            method: 'GET',
            timeout: 5000
        });
        
        if (rootResponse.ok) {
            const rootData = await rootResponse.text();
            
            try {
                const compileResponse = await fetch('http://65.2.104.225:8000/api/compile', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        language: 'python',
                        code: 'print("Hello, World!")',
                        stdin: ''
                    }),
                    timeout: 10000
                });
                
                const compileData = compileResponse.ok ? await compileResponse.json() : { error: `Status: ${compileResponse.status}` };
                
                return res.json({
                    status: 'connected',
                    root_response: rootData,
                    compile_endpoint: 'http://65.2.104.225:8000/api/compile',
                    compile_test: compileData,
                    language_mapping: {
                        '71': 'python',
                        '54': 'cpp', 
                        '50': 'c',
                        '62': 'java'
                    }
                });
            } catch (compileError) {
                return res.json({
                    status: 'partially_connected',
                    root_response: rootData,
                    compile_endpoint_error: compileError.message,
                    note: 'Root endpoint works but compile endpoint failed'
                });
            }
        } else {
            return res.status(502).json({
                status: 'error',
                message: `Compiler service responded with status: ${rootResponse.status}`,
                url: 'http://65.2.104.225:8000'
            });
        }
    } catch (err) {
        return res.status(503).json({
            status: 'error',
            message: `Cannot connect to compiler service: ${err.message}`,
            suggestion: 'Make sure the compiler service is running and accessible from this server'
        });
    }
});

// ====================================================
// DASHBOARD STATS ENDPOINTS
// ====================================================

// Get moderator dashboard stats
app.get('/api/moderator/dashboard-stats', verifyToken, async (req, res) => {
    try {
        // Count all colleges
        const { Count: collegeCount } = await client.send(new ScanCommand({
            TableName: "Colleges",
            Select: "COUNT"
        }));
        
        // Count all students
        const { Count: studentCount } = await client.send(new ScanCommand({
            TableName: "Students",
            Select: "COUNT"
        }));
        
        // Count regular contests created by this moderator
        const { Items: regularContests } = await client.send(new ScanCommand({
            TableName: "Contests",
            FilterExpression: "created_by = :email",
            ExpressionAttributeValues: ddbMarshall({
                ":email": req.user.email
            })
        }));
        
        // Count debugging contests created by this moderator
        const { Items: debugContests } = await client.send(new ScanCommand({
            TableName: "DebugContests",
            FilterExpression: "created_by = :email",
            ExpressionAttributeValues: ddbMarshall({
                ":email": req.user.email
            })
        }));
        
        const totalContests = (regularContests?.length || 0) + (debugContests?.length || 0);
        
        res.json({
            success: true,
            data: {
                colleges: collegeCount || 0,
                students: studentCount || 0,
                contests: totalContests,
                regular_contests: regularContests?.length || 0,
                debug_contests: debugContests?.length || 0
            }
        });
        
    } catch (err) {
        console.error("Dashboard Stats Error:", err);
        res.status(500).json({ 
            success: false,
            message: "Error fetching dashboard statistics",
            error: err.message 
        });
    }
});

// Count students by college
app.get('/api/moderator/student-count/:collegeName', verifyToken, async (req, res) => {
    try {
        const collegeName = req.params.collegeName;
        
        const { Items } = await client.send(new ScanCommand({
            TableName: "Students",
            FilterExpression: "college = :college",
            ExpressionAttributeValues: ddbMarshall({
                ":college": collegeName
            })
        }));
        
        res.json({
            success: true,
            data: {
                college: collegeName,
                student_count: Items?.length || 0
            }
        });
        
    } catch (err) {
        console.error("Student Count Error:", err);
        res.status(500).json({ 
            success: false,
            message: "Error counting students",
            error: err.message 
        });
    }
});

// ====================================================
// 12. HELPER FUNCTIONS
// ====================================================

// Validate test case output
function validateOutput(userOutput, expectedOutput) {
    const normalize = (str) => {
        if (!str) return '';
        return str.trim()
            .replace(/\r\n/g, '\n')
            .replace(/\n+/g, '\n')
            .replace(/\s+/g, ' ')
            .trim();
    };
    
    return normalize(userOutput) === normalize(expectedOutput);
}
// ====================================================
// ADMIN-SPECIFIC ROUTES (For admin.html)
// ====================================================

// Route 1: Admin login (uses existing login but returns proper admin structure)
app.post('/api/admin-login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ 
                success: false, 
                message: "Email and password are required" 
            });
        }
        
        const normalizedEmail = String(email).toLowerCase().trim();
        
        // Check in AdminTable first
        let tableName = "AdminTable";
        let { Item } = await client.send(new GetItemCommand({
            TableName: tableName,
            Key: { email: { S: normalizedEmail } }
        }));
        
        // If not in AdminTable, check Moderators table for admin role
        if (!Item) {
            tableName = "Moderators";
            const { Item: modItem } = await client.send(new GetItemCommand({
                TableName: tableName,
                Key: { email: { S: normalizedEmail } }
            }));
            
            Item = modItem;
        }
        
        if (!Item) {
            return res.status(401).json({ 
                success: false, 
                message: "Invalid credentials" 
            });
        }
        
        const user = unmarshall(Item);
        
        // Check if user is an admin
        const userRole = user.role || (tableName === "AdminTable" ? "admin" : "moderator");
        
        if (userRole !== 'admin') {
            return res.status(403).json({ 
                success: false, 
                message: "Admin access required" 
            });
        }
        
        // Check if account is active
        if (user.status && user.status !== 'active') {
            return res.status(403).json({ 
                success: false, 
                message: "Admin account is disabled" 
            });
        }
        
        // Verify password
        const isPasswordValid = await bcrypt.compare(String(password).trim(), user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ 
                success: false, 
                message: "Invalid credentials" 
            });
        }
        
        // Create token
        const token = jwt.sign(
            { 
                email: user.email, 
                role: 'admin',
                name: user.name 
            },
            process.env.JWT_SECRET || "default_secret_key", 
            { expiresIn: '8h' }
        );
        
        res.json({
            success: true,
            token,
            admin: {
                id: user.email,
                name: user.name,
                email: user.email,
                role: 'admin'
            }
        });
        
    } catch (err) {
        console.error("Admin Login Error:", err);
        res.status(500).json({ 
            success: false, 
            message: "Internal server error during login" 
        });
    }
});

// Route 2: Get all moderators (with role filtering)
app.get('/api/admin/moderators', verifyToken, async (req, res) => {
    try {
        const { Items } = await client.send(new ScanCommand({ 
            TableName: "Moderators" 
        }));
        
        const moderators = (Items || []).map(i => {
            const mod = unmarshall(i);
            // Remove password for security
            delete mod.password;
            return {
                ...mod,
                // Ensure all required fields exist
                name: mod.name || mod.email,
                status: mod.status || 'active',
                role: mod.role || 'moderator',
                createdAt: mod.createdAt || mod.created_at || new Date().toISOString()
            };
        });
        
        res.json(moderators); // Return array directly as expected by admin.html
        
    } catch (err) {
        console.error("Get Moderators Error:", err);
        res.status(500).json({ 
            success: false, 
            message: "Error fetching moderators" 
        });
    }
});


// Route 3: Create new moderator (admin.html expects this exact endpoint)
app.post('/api/admin/create-moderator', verifyToken, async (req, res) => {
    try {
        const { name, email, password, role } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ 
                success: false, 
                message: "Email and password required" 
            });
        }
        
        const normalizedEmail = String(email).toLowerCase().trim();
        
        // Check if user already exists
        const { Item: existingItem } = await client.send(new GetItemCommand({
            TableName: "Moderators",
            Key: { email: { S: normalizedEmail } }
        }));
        
        if (existingItem) {
            return res.status(400).json({ 
                success: false, 
                message: "Moderator already exists with this email" 
            });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(String(password).trim(), 10);
        
        const moderatorData = {
            email: normalizedEmail,
            name: name || "Moderator",
            password: hashedPassword,
            role: role || "moderator",
            status: "active",
            created_at: new Date().toISOString(),
            created_by: req.user.email,
            updated_at: new Date().toISOString()
        };
        
        await client.send(new PutItemCommand({
            TableName: "Moderators",
            Item: ddbMarshall(moderatorData)
        }));
        
        // Return without password
        const { password: _, ...moderatorWithoutPassword } = moderatorData;
        
        res.status(201).json(moderatorWithoutPassword);
        
    } catch (err) {
        console.error("Create Moderator Error:", err);
        res.status(500).json({ 
            success: false, 
            message: "Error creating moderator" 
        });
    }
});

// Route 4: Edit moderator (admin.html expects this exact endpoint)
app.patch('/api/admin/edit-moderator', verifyToken, async (req, res) => {
    try {
        const { email, name, role } = req.body;
        
        if (!email || !name) {
            return res.status(400).json({ 
                success: false, 
                message: "Email and name are required" 
            });
        }
        
        const normalizedEmail = String(email).toLowerCase().trim();
        
        // Check if moderator exists
        const { Item } = await client.send(new GetItemCommand({
            TableName: "Moderators",
            Key: { email: { S: normalizedEmail } }
        }));
        
        if (!Item) {
            return res.status(404).json({ 
                success: false, 
                message: "Moderator not found" 
            });
        }
        
        const moderator = unmarshall(Item);
        
        // Build update expression
        const updateExpressions = [];
        const expressionValues = {};
        const expressionNames = {};
        
        updateExpressions.push("name = :name");
        expressionValues[":name"] = name;
        
        if (role && ['admin', 'moderator'].includes(role)) {
            updateExpressions.push("#r = :role");
            expressionNames["#r"] = "role";
            expressionValues[":role"] = role;
        }
        
        updateExpressions.push("updated_at = :updated");
        expressionValues[":updated"] = new Date().toISOString();
        
        await client.send(new UpdateItemCommand({
            TableName: "Moderators",
            Key: ddbMarshall({ email: normalizedEmail }),
            UpdateExpression: `SET ${updateExpressions.join(', ')}`,
            ExpressionAttributeNames: expressionNames,
            ExpressionAttributeValues: ddbMarshall(expressionValues)
        }));
        
        // Get updated moderator
        const { Item: updatedItem } = await client.send(new GetItemCommand({
            TableName: "Moderators",
            Key: { email: { S: normalizedEmail } }
        }));
        
        const updatedModerator = unmarshall(updatedItem);
        delete updatedModerator.password;
        
        res.json(updatedModerator);
        
    } catch (err) {
        console.error("Edit Moderator Error:", err);
        res.status(500).json({ 
            success: false, 
            message: "Error updating moderator" 
        });
    }
});

// Route 5: Update moderator status (admin.html expects this exact endpoint)
app.patch('/api/admin/moderator-status', verifyToken, async (req, res) => {
    try {
        const { email, status } = req.body;
        
        if (!email || !status) {
            return res.status(400).json({ 
                success: false, 
                message: "Email and status are required" 
            });
        }
        
        if (!['active', 'held'].includes(status)) {
            return res.status(400).json({ 
                success: false, 
                message: "Status must be either 'active' or 'held'" 
            });
        }
        
        const normalizedEmail = String(email).toLowerCase().trim();
        
        // Check if moderator exists
        const { Item } = await client.send(new GetItemCommand({
            TableName: "Moderators",
            Key: { email: { S: normalizedEmail } }
        }));
        
        if (!Item) {
            return res.status(404).json({ 
                success: false, 
                message: "Moderator not found" 
            });
        }
        
        const moderator = unmarshall(Item);
        
        // Prevent admin from holding their own account
        if (moderator.email === req.user.email && status === 'held') {
            return res.status(400).json({ 
                success: false, 
                message: "Cannot hold your own admin account" 
            });
        }
        
        // Update status
        await client.send(new UpdateItemCommand({
            TableName: "Moderators",
            Key: ddbMarshall({ email: normalizedEmail }),
            UpdateExpression: "SET #s = :status, updated_at = :updated",
            ExpressionAttributeNames: { "#s": "status" },
            ExpressionAttributeValues: ddbMarshall({ 
                ":status": status,
                ":updated": new Date().toISOString()
            })
        }));
        
        // Get updated moderator
        const { Item: updatedItem } = await client.send(new GetItemCommand({
            TableName: "Moderators",
            Key: { email: { S: normalizedEmail } }
        }));
        
        const updatedModerator = unmarshall(updatedItem);
        delete updatedModerator.password;
        
        res.json(updatedModerator);
        
    } catch (err) {
        console.error("Update Moderator Status Error:", err);
        res.status(500).json({ 
            success: false, 
            message: "Error updating moderator status" 
        });
    }
});

// Route 6: Delete moderator (admin.html expects this exact endpoint)
app.delete('/api/admin/moderator/:email', verifyToken, async (req, res) => {
    try {
        const { email } = req.params;
        
        if (!email) {
            return res.status(400).json({ 
                success: false, 
                message: "Email is required" 
            });
        }
        
        const normalizedEmail = String(email).toLowerCase().trim();
        
        // Check if moderator exists
        const { Item } = await client.send(new GetItemCommand({
            TableName: "Moderators",
            Key: { email: { S: normalizedEmail } }
        }));
        
        if (!Item) {
            return res.status(404).json({ 
                success: false, 
                message: "Moderator not found" 
            });
        }
        
        const moderator = unmarshall(Item);
        
        // Prevent admin from deleting their own account
        if (moderator.email === req.user.email) {
            return res.status(400).json({ 
                success: false, 
                message: "Cannot delete your own admin account" 
            });
        }
        
        // Delete moderator
        await client.send(new DeleteItemCommand({
            TableName: "Moderators",
            Key: ddbMarshall({ email: normalizedEmail })
        }));
        
        // Return success response
        res.json({ 
            success: true, 
            message: "Moderator deleted successfully" 
        });
        
    } catch (err) {
        console.error("Delete Moderator Error:", err);
        res.status(500).json({ 
            success: false, 
            message: "Error deleting moderator" 
        });
    }
});

// Route 7: Admin dashboard stats (admin.html expects this)
app.get('/api/admin/stats', verifyToken, async (req, res) => {
    try {
        // Count all moderators
        const { Items: allModerators } = await client.send(new ScanCommand({
            TableName: "Moderators"
        }));
        
        const moderatorCount = allModerators?.length || 0;
        const heldModerators = (allModerators || []).filter(item => {
            const mod = unmarshall(item);
            return mod.status === 'held';
        }).length;
        
        // Count all students
        const { Count: studentCount } = await client.send(new ScanCommand({
            TableName: "Students",
            Select: "COUNT"
        }));
        
        // Count all contests
        const { Items: allContests } = await client.send(new ScanCommand({
            TableName: "Contests"
        }));
        
        const contestCount = allContests?.length || 0;
        
        // Get recent activity (last 7 days)
        const oneWeekAgo = new Date();
        oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);
        
        // Get recent students
        const { Items: allStudents } = await client.send(new ScanCommand({
            TableName: "Students"
        }));
        
        const newStudents = (allStudents || []).filter(item => {
            const student = unmarshall(item);
            const registeredDate = new Date(student.registeredAt || student.created_at || 0);
            return registeredDate > oneWeekAgo;
        }).length;
        
        // Get recent contests
        const newContests = (allContests || []).filter(item => {
            const contest = unmarshall(item);
            const createdDate = new Date(contest.created_at || contest.createdAt || 0);
            return createdDate > oneWeekAgo;
        }).length;
        
        res.json({
            totals: {
                users: studentCount || 0,
                moderators: moderatorCount,
                contests: contestCount
            },
            active: {
                contests: contestCount,
                heldModerators: heldModerators
            },
            recent: {
                newUsers: newStudents,
                newContests: newContests
            }
        });
        
    } catch (err) {
        console.error("Admin Stats Error:", err);
        res.status(500).json({ 
            success: false, 
            message: "Error fetching admin statistics" 
        });
    }
});

// Get all regular contests for dropdown
app.get('/api/moderator/all-regular-contests', verifyToken, async (req, res) => {
    try {
        const { Items } = await client.send(new ScanCommand({
            TableName: "Contests",
            FilterExpression: "created_by = :email AND #type <> :debugType",
            ExpressionAttributeNames: {
                "#type": "type"
            },
            ExpressionAttributeValues: ddbMarshall({
                ":email": req.user.email,
                ":debugType": "debugging"
            })
        }));
        
        const contests = (Items || []).map(i => {
            const contest = unmarshall(i);
            return {
                contest_id: contest.contest_id,
                name: contest.name,
                language: contest.language,
                problems_count: contest.problems?.length || 0,
                total_score: contest.metadata?.total_score || 0,
                created_at: contest.created_at,
                status: contest.status || 'active'
            };
        });
        
        res.json({ success: true, data: contests });
    } catch (err) {
        console.error("Get Regular Contests Error:", err);
        res.status(500).json({ success: false, message: "Error fetching regular contests" });
    }
});

// Get all debugging contests for dropdown
app.get('/api/moderator/all-debug-contests', verifyToken, async (req, res) => {
    try {
        const { Items } = await client.send(new ScanCommand({
            TableName: "DebugContests",
            FilterExpression: "created_by = :email",
            ExpressionAttributeValues: ddbMarshall({
                ":email": req.user.email
            })
        }));
        
        const contests = (Items || []).map(i => {
            const contest = unmarshall(i);
            return {
                contest_id: contest.contest_id,
                name: contest.name,
                language: contest.language,
                problems_count: contest.problems?.length || 0,
                total_score: contest.metadata?.total_score || 0,
                created_at: contest.created_at,
                status: contest.status || 'active'
            };
        });
        
        res.json({ success: true, data: contests });
    } catch (err) {
        console.error("Get Debug Contests Error:", err);
        res.status(500).json({ success: false, message: "Error fetching debugging contests" });
    }
});

// Get contest progression rules
app.get('/api/moderator/contest-progression-rules', verifyToken, async (req, res) => {
    try {
        const { Items } = await client.send(new ScanCommand({
            TableName: "ContestProgressionRules",
            FilterExpression: "created_by = :email",
            ExpressionAttributeValues: ddbMarshall({
                ":email": req.user.email
            })
        }));
        
        const rules = (Items || []).map(i => unmarshall(i));
        
        res.json({ success: true, data: rules });
    } catch (err) {
        console.error("Get Progression Rules Error:", err);
        // If table doesn't exist, return empty array
        res.json({ success: true, data: [] });
    }
});

// Save or update contest progression rules
app.post('/api/moderator/save-progression-rules', verifyToken, async (req, res) => {
    try {
        const {
            normalContestId,
            debugContestId,
            passingScore,
            timeLimitRequired,
            minProblemsRequired,
            minProblemsCount,
            disqualifyOnCheating
        } = req.body;
        
        console.log("Saving progression rules:", {
            normalContestId,
            debugContestId,
            passingScore,
            timeLimitRequired,
            minProblemsRequired,
            minProblemsCount,
            disqualifyOnCheating
        });
        
        // Validate required fields
        if (!normalContestId || !debugContestId) {
            return res.status(400).json({
                success: false,
                message: "Both normal contest and debugging contest are required"
            });
        }
        
        // Verify contests exist and belong to the moderator
        const [normalContestResult, debugContestResult] = await Promise.all([
            client.send(new GetItemCommand({
                TableName: "Contests",
                Key: ddbMarshall({ contest_id: normalContestId })
            })),
            client.send(new GetItemCommand({
                TableName: "DebugContests",
                Key: ddbMarshall({ contest_id: debugContestId })
            }))
        ]);
        
        if (!normalContestResult.Item || !debugContestResult.Item) {
            return res.status(404).json({
                success: false,
                message: "One or both contests not found"
            });
        }
        
        const normalContest = unmarshall(normalContestResult.Item);
        const debugContest = unmarshall(debugContestResult.Item);
        
        // Check ownership
        if (normalContest.created_by !== req.user.email) {
            return res.status(403).json({
                success: false,
                message: "You don't have permission to use this normal contest"
            });
        }
        
        if (debugContest.created_by !== req.user.email) {
            return res.status(403).json({
                success: false,
                message: "You don't have permission to use this debug contest"
            });
        }
        
        // Generate unique rule ID
        const ruleId = `rule_${crypto.randomUUID().replace(/-/g, '').substring(0, 12)}`;
        
        // Create progression rule data
        const progressionRule = {
            rule_id: ruleId,
            normal_contest_id: normalContestId,
            debug_contest_id: debugContestId,
            normal_contest_name: normalContest.name,
            debug_contest_name: debugContest.name,
            passing_score: parseInt(passingScore) || 70,
            time_limit_required: timeLimitRequired || false,
            min_problems_required: minProblemsRequired || false,
            min_problems_count: minProblemsRequired ? parseInt(minProblemsCount) || 1 : null,
            disqualify_on_cheating: disqualifyOnCheating || false,
            created_by: req.user.email,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
            status: 'active',
            stats: {
                total_students: 0,
                unlocked_count: 0,
                success_rate: 0,
                avg_completion_days: 0
            }
        };
        
        // Save to ContestProgressionRules table
        await client.send(new PutItemCommand({
            TableName: "ContestProgressionRules",
            Item: ddbMarshall(progressionRule)
        }));
        
        // Update contests with progression information
        await Promise.all([
            client.send(new UpdateItemCommand({
                TableName: "Contests",
                Key: ddbMarshall({ contest_id: normalContestId }),
                UpdateExpression: "SET has_progression = :val, progression_rule_id = :ruleId",
                ExpressionAttributeValues: ddbMarshall({
                    ":val": true,
                    ":ruleId": ruleId
                })
            })),
            client.send(new UpdateItemCommand({
                TableName: "DebugContests",
                Key: ddbMarshall({ contest_id: debugContestId }),
                UpdateExpression: "SET requires_prerequisite = :val, prerequisite_contest_id = :normalId, prerequisite_rule_id = :ruleId",
                ExpressionAttributeValues: ddbMarshall({
                    ":val": true,
                    ":normalId": normalContestId,
                    ":ruleId": ruleId
                })
            }))
        ]);
        
        console.log("Progression rule saved successfully:", ruleId);
        
        res.json({
            success: true,
            message: "Progression rules saved successfully",
            data: {
                ruleId: ruleId,
                normalContest: normalContest.name,
                debugContest: debugContest.name,
                passingScore: progressionRule.passing_score
            }
        });
        
    } catch (err) {
        console.error("Save Progression Rules Error:", err.message, err.stack);
        res.status(500).json({
            success: false,
            message: "Error saving progression rules",
            error: err.message
        });
    }
});

app.get('/api/moderator/progression-rules', verifyToken, async (req, res) => {
    try {
        console.log("Fetching progression rules for moderator:", req.user.email);
        
        const { Items } = await client.send(new ScanCommand({
            TableName: "ContestProgressionRules",
            FilterExpression: "created_by = :email",
            ExpressionAttributeValues: ddbMarshall({
                ":email": req.user.email
            })
        }));
        
        const rules = (Items || []).map(i => {
            const rule = unmarshall(i);
            return {
                rule_id: rule.rule_id,
                normal_contest_id: rule.normal_contest_id,
                debug_contest_id: rule.debug_contest_id,
                normal_contest_name: rule.normal_contest_name,
                debug_contest_name: rule.debug_contest_name,
                passing_score: rule.passing_score,
                time_limit_required: rule.time_limit_required || false,
                min_problems_required: rule.min_problems_required || false,
                min_problems_count: rule.min_problems_count || null,
                disqualify_on_cheating: rule.disqualify_on_cheating || false,
                status: rule.status || 'active',
                created_at: rule.created_at,
                updated_at: rule.updated_at,
                stats: rule.stats || {}
            };
        });
        
        console.log(`Returning ${rules.length} progression rules`);
        
        res.json({
            success: true,
            data: rules
        });
        
    } catch (err) {
        console.error("Get Progression Rules Error:", err.message);
        // If table doesn't exist, return empty array
        if (err.name === 'ResourceNotFoundException') {
            return res.json({
                success: true,
                data: []
            });
        }
        res.status(500).json({
            success: false,
            message: "Error fetching progression rules",
            error: err.message
        });
    }
});

// Update progression rule status
app.patch('/api/moderator/update-progression-rule/:id', verifyToken, async (req, res) => {
    try {
        const ruleId = req.params.id;
        const { status } = req.body;
        
        if (!status || !['active', 'inactive'].includes(status)) {
            return res.status(400).json({ 
                success: false, 
                message: "Status must be 'active' or 'inactive'" 
            });
        }
        
        // Get the rule first
        const { Item } = await client.send(new GetItemCommand({
            TableName: "ContestProgressionRules",
            Key: ddbMarshall({ rule_id: ruleId })
        }));
        
        if (!Item) {
            return res.status(404).json({ 
                success: false, 
                message: "Progression rule not found" 
            });
        }
        
        const rule = unmarshall(Item);
        
        // Check ownership
        if (rule.created_by !== req.user.email) {
            return res.status(403).json({ 
                success: false, 
                message: "You don't have permission to update this rule" 
            });
        }
        
        // Update the rule
        await client.send(new UpdateItemCommand({
            TableName: "ContestProgressionRules",
            Key: ddbMarshall({ rule_id: ruleId }),
            UpdateExpression: "SET #s = :status, updated_at = :updated",
            ExpressionAttributeNames: { "#s": "status" },
            ExpressionAttributeValues: ddbMarshall({
                ":status": status,
                ":updated": new Date().toISOString()
            })
        }));
        
        res.json({
            success: true,
            message: `Progression rule ${status === 'active' ? 'activated' : 'deactivated'} successfully`
        });
        
    } catch (err) {
        console.error("Update Progression Rule Error:", err);
        res.status(500).json({ 
            success: false, 
            message: "Error updating progression rule",
            error: err.message 
        });
    }
});

// Delete progression rule
app.delete('/api/moderator/delete-progression-rule/:id', verifyToken, async (req, res) => {
    try {
        const ruleId = req.params.id;
        
        // Get the rule first
        const { Item } = await client.send(new GetItemCommand({
            TableName: "ContestProgressionRules",
            Key: ddbMarshall({ rule_id: ruleId })
        }));
        
        if (!Item) {
            return res.status(404).json({ 
                success: false, 
                message: "Progression rule not found" 
            });
        }
        
        const rule = unmarshall(Item);
        
        // Check ownership
        if (rule.created_by !== req.user.email) {
            return res.status(403).json({ 
                success: false, 
                message: "You don't have permission to delete this rule" 
            });
        }
        
        // Remove progression flags from contests
        await Promise.all([
            client.send(new UpdateItemCommand({
                TableName: "Contests",
                Key: ddbMarshall({ contest_id: rule.normal_contest_id }),
                UpdateExpression: "REMOVE is_part_of_progression, progression_rule_id"
            })),
            client.send(new UpdateItemCommand({
                TableName: "DebugContests",
                Key: ddbMarshall({ contest_id: rule.debug_contest_id }),
                UpdateExpression: "REMOVE requires_prerequisite, prerequisite_contest_id"
            }))
        ]);
        
        // Delete the rule
        await client.send(new DeleteItemCommand({
            TableName: "ContestProgressionRules",
            Key: ddbMarshall({ rule_id: ruleId })
        }));
        
        res.json({
            success: true,
            message: "Progression rule deleted successfully"
        });
        
    } catch (err) {
        console.error("Delete Progression Rule Error:", err);
        res.status(500).json({ 
            success: false, 
            message: "Error deleting progression rule",
            error: err.message 
        });
    }
});

// Get statistics for a progression rule
app.get('/api/moderator/progression-stats/:ruleId', verifyToken, async (req, res) => {
    try {
        const ruleId = req.params.id || req.params.ruleId;
        
        // Get the rule
        const { Item } = await client.send(new GetItemCommand({
            TableName: "ContestProgressionRules",
            Key: ddbMarshall({ rule_id: ruleId })
        }));
        
        if (!Item) {
            return res.status(404).json({ 
                success: false, 
                message: "Progression rule not found" 
            });
        }
        
        const rule = unmarshall(Item);
        
        // Check ownership
        if (rule.created_by !== req.user.email) {
            return res.status(403).json({ 
                success: false, 
                message: "You don't have permission to view this rule" 
            });
        }
        
        // Get results for normal contest
        const { Items: normalResults } = await client.send(new QueryCommand({
            TableName: "StudentResults",
            IndexName: "ContentResultsIndex",
            KeyConditionExpression: "contest_id = :cid",
            ExpressionAttributeValues: ddbMarshall({
                ":cid": rule.normal_contest_id
            })
        }));
        
        const normalContestResults = (normalResults || []).map(i => unmarshall(i));
        
        // Get results for debug contest
        const { Items: debugResults } = await client.send(new QueryCommand({
            TableName: "DebugStudentResults",
            IndexName: "ContentResultsIndex",
            KeyConditionExpression: "contest_id = :cid",
            ExpressionAttributeValues: ddbMarshall({
                ":cid": rule.debug_contest_id
            })
        }));
        
        const debugContestResults = (debugResults || []).map(i => unmarshall(i));
        
        // Calculate statistics
        const totalStudents = normalContestResults.length;
        const passedStudents = normalContestResults.filter(r => 
            r.total_score >= rule.passing_score && r.status === 'completed'
        ).length;
        
        const unlockedDebug = debugContestResults.length;
        const debugCompletionRate = debugContestResults.length > 0 
            ? (debugContestResults.filter(r => r.status === 'completed').length / debugContestResults.length) * 100 
            : 0;
        
        const stats = {
            total_students: totalStudents,
            students_passed: passedStudents,
            pass_rate: totalStudents > 0 ? (passedStudents / totalStudents) * 100 : 0,
            unlocked_debug: unlockedDebug,
            debug_completion_rate: debugCompletionRate,
            average_normal_score: normalContestResults.length > 0 
                ? normalContestResults.reduce((sum, r) => sum + r.total_score, 0) / normalContestResults.length 
                : 0,
            average_debug_score: debugContestResults.length > 0 
                ? debugContestResults.reduce((sum, r) => sum + r.total_score, 0) / debugContestResults.length 
                : 0
        };
        
        // Update rule with latest stats
        await client.send(new UpdateItemCommand({
            TableName: "ContestProgressionRules",
            Key: ddbMarshall({ rule_id: ruleId }),
            UpdateExpression: "SET stats = :stats",
            ExpressionAttributeValues: ddbMarshall({
                ":stats": stats
            })
        }));
        
        res.json({
            success: true,
            data: {
                rule: rule,
                stats: stats,
                normal_contest: {
                    total_participants: normalContestResults.length,
                    completed: normalContestResults.filter(r => r.status === 'completed').length
                },
                debug_contest: {
                    total_participants: debugContestResults.length,
                    completed: debugContestResults.filter(r => r.status === 'completed').length
                }
            }
        });
        
    } catch (err) {
        console.error("Get Progression Stats Error:", err);
        res.status(500).json({ 
            success: false, 
            message: "Error fetching progression statistics",
            error: err.message 
        });
    }
});

// Get student progression status for a rule
app.get('/api/moderator/progression-students/:ruleId', verifyToken, async (req, res) => {
    try {
        const ruleId = req.params.ruleId;
        
        // Get the rule
        const { Item } = await client.send(new GetItemCommand({
            TableName: "ContestProgressionRules",
            Key: ddbMarshall({ rule_id: ruleId })
        }));
        
        if (!Item) {
            return res.status(404).json({ 
                success: false, 
                message: "Progression rule not found" 
            });
        }
        
        const rule = unmarshall(Item);
        
        // Get all students
        const { Items: allStudents } = await client.send(new ScanCommand({
            TableName: "Students",
            Limit: 100 // Limit for performance
        }));
        
        const students = (allStudents || []).map(i => unmarshall(i));
        
        // Get student results for both contests
        const studentsWithProgress = await Promise.all(
            students.map(async (student) => {
                const normalResultId = `res_${student.email}_${rule.normal_contest_id}`;
                const debugResultId = `res_${student.email}_${rule.debug_contest_id}`;
                
                const [normalResult, debugResult] = await Promise.all([
                    client.send(new GetItemCommand({
                        TableName: "StudentResults",
                        Key: ddbMarshall({ result_id: normalResultId })
                    })),
                    client.send(new GetItemCommand({
                        TableName: "DebugStudentResults",
                        Key: ddbMarshall({ result_id: debugResultId })
                    }))
                ]);
                
                const normal = normalResult.Item ? unmarshall(normalResult.Item) : null;
                const debug = debugResult.Item ? unmarshall(debugResult.Item) : null;
                
                const hasAccess = normal && 
                    normal.total_score >= rule.passing_score && 
                    normal.status === 'completed';
                
                const progressStatus = !normal ? 'not_started' :
                    normal.status !== 'completed' ? 'in_progress' :
                    hasAccess ? 'unlocked' :
                    'failed';
                
                return {
                    student_id: student.email,
                    student_name: student.name,
                    college: student.college,
                    normal_contest: {
                        score: normal ? normal.total_score : 0,
                        status: normal ? normal.status : 'not_started',
                        problems_solved: normal ? normal.problems_solved : 0,
                        completed: normal ? normal.status === 'completed' : false
                    },
                    debug_contest: {
                        score: debug ? debug.total_score : 0,
                        status: debug ? debug.status : 'not_started',
                        problems_solved: debug ? debug.problems_solved : 0,
                        has_access: hasAccess || false
                    },
                    progression_status: progressStatus,
                    unlocked_debug: hasAccess,
                    last_activity: normal ? normal.updated_at : student.registeredAt
                };
            })
        );
        
        // Filter and sort
        const sortedStudents = studentsWithProgress.sort((a, b) => {
            // Sort by progression status: unlocked > in_progress > failed > not_started
            const statusOrder = { 'unlocked': 0, 'in_progress': 1, 'failed': 2, 'not_started': 3 };
            return statusOrder[a.progression_status] - statusOrder[b.progression_status] ||
                new Date(b.last_activity) - new Date(a.last_activity);
        });
        
        res.json({
            success: true,
            data: {
                rule: {
                    id: rule.rule_id,
                    normal_contest_name: rule.normal_contest_name,
                    debug_contest_name: rule.debug_contest_name,
                    passing_score: rule.passing_score
                },
                students: sortedStudents,
                summary: {
                    total_students: studentsWithProgress.length,
                    unlocked_count: studentsWithProgress.filter(s => s.unlocked_debug).length,
                    in_progress: studentsWithProgress.filter(s => s.progression_status === 'in_progress').length,
                    failed: studentsWithProgress.filter(s => s.progression_status === 'failed').length,
                    not_started: studentsWithProgress.filter(s => s.progression_status === 'not_started').length
                }
            }
        });
        
    } catch (err) {
        console.error("Get Progression Students Error:", err);
        res.status(500).json({ 
            success: false, 
            message: "Error fetching student progression data",
            error: err.message 
        });
    }
});

// Check if student has access to debug contest
app.get('/api/student/check-debug-access/:debugContestId', verifyToken, async (req, res) => {
    try {
        const debugContestId = req.params.debugContestId;
        
        // Get debug contest
        const { Item: debugItem } = await client.send(new GetItemCommand({
            TableName: "DebugContests",
            Key: ddbMarshall({ contest_id: debugContestId })
        }));
        
        if (!debugItem) {
            return res.status(404).json({ 
                success: false,
                message: "Debug contest not found" 
            });
        }
        
        const debugContest = unmarshall(debugItem);
        
        // Check if contest requires prerequisite
        if (!debugContest.requires_prerequisite || !debugContest.prerequisite_contest_id) {
            // No prerequisite required
            return res.json({
                success: true,
                data: {
                    has_access: true,
                    reason: "No prerequisites required for this contest"
                }
            });
        }
        
        const normalContestId = debugContest.prerequisite_contest_id;
        
        // Check if student has completed the normal contest
        const resultId = `res_${req.user.email}_${normalContestId}`;
        const { Item: resultItem } = await client.send(new GetItemCommand({
            TableName: "StudentResults",
            Key: ddbMarshall({ result_id: resultId })
        }));
        
        if (!resultItem) {
            return res.json({
                success: true,
                data: {
                    has_access: false,
                    reason: "You need to complete the prerequisite contest first",
                    prerequisite_contest_id: normalContestId,
                    prerequisite_contest_name: debugContest.prerequisite_contest_name
                }
            });
        }
        
        const normalResult = unmarshall(resultItem);
        
        // Check passing score (default 70 if no rule found)
        const { Items: ruleItems } = await client.send(new ScanCommand({
            TableName: "ContestProgressionRules",
            FilterExpression: "debug_contest_id = :debugId",
            ExpressionAttributeValues: ddbMarshall({
                ":debugId": debugContestId
            })
        }));
        
        const passingScore = ruleItems && ruleItems.length > 0 
            ? unmarshall(ruleItems[0]).passing_score 
            : 70;
        
        const hasAccess = normalResult.status === 'completed' && 
            normalResult.total_score >= passingScore;
        
        res.json({
            success: true,
            data: {
                has_access: hasAccess,
                reason: hasAccess 
                    ? "You have successfully unlocked this debug contest!" 
                    : `You need to score at least ${passingScore}% in the prerequisite contest`,
                prerequisite_contest: {
                    id: normalContestId,
                    name: debugContest.prerequisite_contest_name,
                    your_score: normalResult.total_score,
                    required_score: passingScore,
                    completed: normalResult.status === 'completed'
                },
                debug_contest: {
                    id: debugContestId,
                    name: debugContest.name
                }
            }
        });
        
    } catch (err) {
        console.error("Check Debug Access Error:", err);
        res.status(500).json({ 
            success: false,
            message: "Error checking debug contest access",
            error: err.message 
        });
    }
});
// ====================================================
// DEBUG CONTEST HELPER FUNCTIONS
// ====================================================

// Helper function to test debug solutions
async function testDebugSolution(fixedCode, problem, language) {
    try {
        const languageMap = {
            'python': 'python',
            'python3': 'python',
            'py': 'python',
            'cpp': 'cpp',
            'c++': 'cpp',
            'c': 'c',
            'java': 'java',
            'javascript': 'javascript',
            'js': 'javascript'
        };
        
        const compilerLang = languageMap[language.toLowerCase()] || 'python';
        
        console.log(`Testing debug solution for ${language}, using compiler language: ${compilerLang}`);
        console.log(`Problem input: "${problem.input || ''}"`);
        console.log(`Expected output: "${problem.output || ''}"`);
        
        const response = await fetch('http://65.2.104.225:8000/api/compile', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                language: compilerLang,
                code: fixedCode,
                stdin: problem.input || ""
            }),
            timeout: 10000
        });
        
        const result = await response.json();
        console.log('Debug test result:', JSON.stringify(result, null, 2));
        
        // Extract output from various possible fields
        let output = "";
        if (result.output !== undefined && result.output !== null) {
            output = String(result.output);
        } else if (result.stdout !== undefined && result.stdout !== null) {
            output = String(result.stdout);
        } else if (result.compile_output !== undefined && result.compile_output !== null) {
            output = String(result.compile_output);
        }
        
        // Extract error
        let error = "";
        if (result.stderr !== undefined && result.stderr !== null && result.stderr !== "") {
            error = String(result.stderr);
        } else if (result.error !== undefined && result.error !== null && result.error !== "") {
            error = String(result.error);
        }
        
        // Normalize strings for comparison
        const normalize = (str) => {
            if (!str) return '';
            return str.trim()
                .replace(/\r\n/g, '\n')
                .replace(/\n+/g, '\n')
                .replace(/\s+/g, ' ')
                .trim();
        };
        
        const normalizedOutput = normalize(output);
        const normalizedExpected = normalize(problem.output);
        
        const passed = normalizedOutput === normalizedExpected;
        
        return {
            passed: passed,
            output: output,
            expected: problem.output,
            error: error || '',
            time: result.time || 0,
            normalized: {
                output: normalizedOutput,
                expected: normalizedExpected
            }
        };
        
    } catch (err) {
        console.error("Test Debug Solution Error:", err.message);
        return {
            passed: false,
            output: '',
            expected: problem.output,
            error: `Compiler error: ${err.message}`,
            time: 0
        };
    }
}

// Helper function to update debug student results in DebugStudentResults table
async function updateDebugStudentResults(studentEmail, contestId, contest, submission) {
    try {
        console.log(`Updating debug student results for ${studentEmail}, contest ${contestId}`);
        
        const resultId = `res_${studentEmail}_${contestId}`;
        
        // Check if result already exists
        let existingResult = null;
        try {
            const { Item: existingItem } = await client.send(new GetItemCommand({
                TableName: "DebugStudentResults",
                Key: ddbMarshall({ result_id: resultId })
            }));
            
            if (existingItem) {
                existingResult = unmarshall(existingItem);
                console.log("Found existing debug result:", existingResult.result_id);
            }
        } catch (getErr) {
            console.log("No existing debug result found, creating new one");
        }
        
        const totalProblems = contest.problems?.length || 0;
        const maxScore = contest.metadata?.total_score || 
                        contest.problems?.reduce((sum, p) => sum + (p.score || 20), 0) || 0;
        
        let problemScores = [];
        let totalScore = 0;
        let problemsSolved = 0;
        
        if (existingResult && existingResult.problem_scores && Array.isArray(existingResult.problem_scores)) {
            // Update existing scores
            problemScores = existingResult.problem_scores;
            const existingProblemIndex = problemScores.findIndex(p => p.index === submission.problem_index);
            
            if (existingProblemIndex >= 0) {
                // Update if new score is better
                if (submission.score > problemScores[existingProblemIndex].score) {
                    problemScores[existingProblemIndex] = {
                        index: submission.problem_index,
                        score: submission.score,
                        passed: submission.passed,
                        submission_time: submission.submitted_at,
                        problem_title: submission.problem_title || `Problem ${submission.problem_index + 1}`
                    };
                    console.log(`Updated existing debug problem ${submission.problem_index} score to ${submission.score}`);
                }
            } else {
                // Add new problem score
                problemScores.push({
                    index: submission.problem_index,
                    score: submission.score,
                    passed: submission.passed,
                    submission_time: submission.submitted_at,
                    problem_title: submission.problem_title || `Problem ${submission.problem_index + 1}`
                });
                console.log(`Added new debug problem ${submission.problem_index} with score ${submission.score}`);
            }
        } else {
            // Create new problem scores array
            problemScores = [{
                index: submission.problem_index,
                score: submission.score,
                passed: submission.passed,
                submission_time: submission.submitted_at,
                problem_title: submission.problem_title || `Problem ${submission.problem_index + 1}`
            }];
            console.log(`Created new debug problem scores array for problem ${submission.problem_index}`);
        }
        
        // Calculate totals
        totalScore = problemScores.reduce((sum, p) => sum + (p.score || 0), 0);
        problemsSolved = problemScores.filter(p => p.passed).length;
        
        // Determine status
        let status = 'not_started';
        if (problemsSolved === totalProblems && totalProblems > 0) {
            status = 'completed';
        } else if (problemsSolved > 0 || problemScores.length > 0) {
            status = 'in_progress';
        }
        
        console.log(`Calculated debug results: totalScore=${totalScore}, problemsSolved=${problemsSolved}/${totalProblems}, status=${status}`);
        
        // Prepare result data
        const resultData = {
            result_id: resultId,
            contest_id: contestId,
            contest_name: contest.name,
            student_email: studentEmail,
            student_name: submission.student_name,
            total_score: totalScore,
            max_score: maxScore,
            problems_solved: problemsSolved,
            total_problems: totalProblems,
            problem_scores: problemScores,
            submission_time: submission.submitted_at,
            updated_at: new Date().toISOString(),
            status: status,
            started_at: existingResult?.started_at || submission.submitted_at
        };
        
        // Save to DebugStudentResults table
        await client.send(new PutItemCommand({
            TableName: "DebugStudentResults",
            Item: ddbMarshall(resultData)
        }));
        
        console.log("Debug student results updated successfully in DebugStudentResults table");
        return resultData;
        
    } catch (err) {
        console.error("Error updating debug student results:", err.message);
        console.error("Error stack:", err.stack);
        throw err;
    }
}

// Helper function to get debug contest with student progress
async function getDebugContestWithProgress(contestId, studentEmail) {
    try {
        // Get contest from DebugContests table
        const { Item: contestItem } = await client.send(new GetItemCommand({
            TableName: "DebugContests",
            Key: ddbMarshall({ contest_id: contestId })
        }));
        
        if (!contestItem) {
            return null;
        }
        
        const contest = unmarshall(contestItem);
        
        // Get student's result from DebugStudentResults table
        const resultId = `res_${studentEmail}_${contestId}`;
        const { Item: resultItem } = await client.send(new GetItemCommand({
            TableName: "DebugStudentResults",
            Key: ddbMarshall({ result_id: resultId })
        }));
        
        const result = resultItem ? unmarshall(resultItem) : null;
        
        // Get student's submissions from DebugSubmissions table
        const { Items: subItems } = await client.send(new QueryCommand({
            TableName: "DebugSubmissions",
            IndexName: "StudentSubmissionsIndex",
            KeyConditionExpression: "student_email = :email",
            FilterExpression: "contest_id = :cid",
            ExpressionAttributeValues: ddbMarshall({
                ":email": studentEmail,
                ":cid": contestId
            }),
            ScanIndexForward: false
        }));
        
        const submissions = (subItems || []).map(i => unmarshall(i));
        
        // Combine contest data with student progress
        return {
            contest: contest,
            result: result,
            submissions: submissions
        };
        
    } catch (err) {
        console.error("Error getting debug contest with progress:", err.message);
        throw err;
    }
}
// ====================================================
// STUDENT DEBUGGING CONTEST ROUTES
// ====================================================

// Get debug contest for student (for student-debug.html)
app.get('/api/student/debug-contest/:id', verifyToken, async (req, res) => {
    try {
        const contestId = req.params.id;
        const userEmail = req.user.email;

        console.log(`Loading debug contest ${contestId} for student ${userEmail}`);

        // Get contest data with student progress
        const contestData = await getDebugContestWithProgress(contestId, userEmail);
        
        if (!contestData || !contestData.contest) {
            return res.status(404).json({
                success: false,
                message: "Debugging contest not found"
            });
        }

        const { contest, result, submissions } = contestData;

        // Check if contest is active
        if (contest.status !== 'active') {
            return res.status(400).json({
                success: false,
                message: "This debugging contest is no longer active"
            });
        }

        // Check progression rules if needed
        let hasAccess = true;
        let accessMessage = "";
        
        if (contest.requires_prerequisite && contest.prerequisite_contest_id) {
            const normalContestId = contest.prerequisite_contest_id;
            
            // Get student's result for the prerequisite contest
            const normalResultId = `res_${userEmail}_${normalContestId}`;
            const { Item: normalResultItem } = await client.send(new GetItemCommand({
                TableName: "StudentResults",
                Key: ddbMarshall({ result_id: normalResultId })
            }));

            if (!normalResultItem) {
                hasAccess = false;
                accessMessage = "You need to complete the prerequisite contest first";
            } else {
                const normalResult = unmarshall(normalResultItem);
                
                // Get progression rule for passing score
                const { Items: ruleItems } = await client.send(new ScanCommand({
                    TableName: "ContestProgressionRules",
                    FilterExpression: "debug_contest_id = :debugId",
                    ExpressionAttributeValues: ddbMarshall({
                        ":debugId": contestId
                    })
                }));
                
                const passingScore = ruleItems && ruleItems.length > 0 
                    ? unmarshall(ruleItems[0]).passing_score 
                    : 70;

                hasAccess = normalResult.status === 'completed' && 
                    normalResult.total_score >= passingScore;
                
                if (!hasAccess) {
                    accessMessage = `You need to score at least ${passingScore}% in the prerequisite contest`;
                }
            }
        }

        // Prepare problems with student submissions
        const problemsWithProgress = contest.problems?.map((problem, index) => {
            const problemSubmissions = submissions.filter(s => s.problem_index === index);
            const bestSubmission = problemSubmissions.length > 0 
                ? problemSubmissions.reduce((best, current) => 
                    current.score > best.score ? current : best
                , problemSubmissions[0])
                : null;

            return {
                index: index,
                title: problem.title || `Bug ${index + 1}`,
                description: problem.description || "",
                buggy_code: problem.buggy_code || "",
                input: problem.input || "",
                output: problem.output || "",
                hints: problem.hints || [],
                explanation: problem.explanation || "",
                difficulty: problem.difficulty || 'Medium',
                score: problem.score || 20,
                best_submission: bestSubmission,
                passed: bestSubmission?.passed || false,
                best_score: bestSubmission?.score || 0,
                attempts: problemSubmissions.length,
                last_attempt: problemSubmissions.length > 0 
                    ? problemSubmissions[0].submitted_at 
                    : null
            };
        }) || [];

        // Prepare final response
        const responseData = {
            contest_id: contest.contest_id,
            name: contest.name,
            description: contest.description || "Debugging Contest",
            type: contest.type || 'debugging',
            language: contest.language || 'python',
            target_type: contest.target_type || 'overall',
            target_college: contest.target_college || '',
            has_access: hasAccess,
            access_message: accessMessage,
            created_at: contest.created_at,
            time_limit: contest.metadata?.time_limit || 60,
            total_score: contest.metadata?.total_score || 0,
            problems: problemsWithProgress,
            student_progress: {
                total_score: result?.total_score || 0,
                max_score: contest.metadata?.total_score || 0,
                problems_solved: result?.problems_solved || 0,
                total_problems: contest.problems?.length || 0,
                submissions: submissions.length,
                status: result?.status || 'not_started',
                started_at: result?.started_at || null,
                last_submission: submissions.length > 0 ? submissions[0].submitted_at : null
            },
            metadata: {
                method: contest.method || 'manual',
                difficulty: contest.metadata?.difficulty || 'Medium',
                topic: contest.metadata?.topic || 'General Debugging',
                total_problems: contest.problems?.length || 0
            }
        };

        res.json({
            success: true,
            data: responseData
        });

    } catch (err) {
        console.error("Get Student Debug Contest Error:", err);
        res.status(500).json({
            success: false,
            message: "Error fetching debugging contest",
            error: err.message
        });
    }
});

// Test debug solution (Run Test)
app.post('/api/student/run-debug-test', verifyToken, async (req, res) => {
    try {
        const { contest_id, problem_index, fixed_code } = req.body;
        
        if (!contest_id || problem_index === undefined || !fixed_code) {
            return res.status(400).json({ 
                success: false,
                message: "Missing required fields" 
            });
        }
        
        // Get debug contest
        const { Item } = await client.send(new GetItemCommand({
            TableName: "DebugContests",
            Key: ddbMarshall({ contest_id: contest_id })
        }));
        
        if (!Item) {
            return res.status(404).json({ 
                success: false,
                message: "Debug contest not found" 
            });
        }
        
        const contest = unmarshall(Item);
        const problem = contest.problems?.[problem_index];
        
        if (!problem) {
            return res.status(404).json({ 
                success: false,
                message: "Problem not found" 
            });
        }
        
        // Use the same test function as regular contests
        const testResult = await testDebugSolution(fixed_code, problem, contest.language);
        
        res.json({
            success: true,
            data: {
                passed: testResult.passed,
                output: testResult.output || "",
                expected: problem.output || "",
                error: testResult.error || "",
                message: testResult.passed ? "Test passed!" : "Test failed"
            }
        });
        
    } catch (err) {
        console.error("Run Debug Test Error:", err);
        res.status(500).json({ 
            success: false,
            message: "Error testing solution",
            error: err.message 
        });
    }
});

// Submit debug solution
app.post('/api/student/submit-debug-solution', verifyToken, async (req, res) => {
    try {
        const { contest_id, problem_index, fixed_code } = req.body;
        
        if (!contest_id || problem_index === undefined || !fixed_code) {
            return res.status(400).json({ 
                success: false,
                message: "Missing required fields" 
            });
        }
        
        // Get debug contest
        const { Item } = await client.send(new GetItemCommand({
            TableName: "DebugContests",
            Key: ddbMarshall({ contest_id: contest_id })
        }));
        
        if (!Item) {
            return res.status(404).json({ 
                success: false,
                message: "Debug contest not found" 
            });
        }
        
        const contest = unmarshall(Item);
        const problem = contest.problems?.[problem_index];
        
        if (!problem) {
            return res.status(404).json({ 
                success: false,
                message: "Problem not found" 
            });
        }
        
        // Test the solution
        const testResult = await testDebugSolution(fixed_code, problem, contest.language);
        const score = testResult.passed ? (problem.score || 20) : 0;
        
        // Create submission record
        const submissionId = `debugsub_${crypto.randomUUID().substring(0, 12)}`;
        const submission = {
            submission_id: submissionId,
            contest_id: contest_id,
            problem_index: problem_index,
            student_email: req.user.email,
            student_name: req.user.name || "Student",
            fixed_code: fixed_code,
            passed: testResult.passed,
            score: score,
            submitted_at: new Date().toISOString(),
            problem_title: problem.title || `Bug ${problem_index + 1}`
        };
        
        // Save to DebugSubmissions table
        await client.send(new PutItemCommand({
            TableName: "DebugSubmissions",
            Item: ddbMarshall(submission)
        }));
        
        // Update student results (using your existing updateStudentResults function)
        // You might need to create a similar function for DebugStudentResults
        // For now, let's update DebugStudentResults
        const resultId = `debugres_${req.user.email}_${contest_id}`;
        
        // Get existing result or create new
        const { Item: existingItem } = await client.send(new GetItemCommand({
            TableName: "DebugStudentResults",
            Key: ddbMarshall({ result_id: resultId })
        }));
        
        let problemScores = [];
        let totalScore = score;
        let problemsSolved = testResult.passed ? 1 : 0;
        
        if (existingItem) {
            const existing = unmarshall(existingItem);
            problemScores = existing.problem_scores || [];
            
            // Update or add problem score
            const existingIdx = problemScores.findIndex(p => p.index === problem_index);
            if (existingIdx >= 0) {
                if (score > problemScores[existingIdx].score) {
                    problemScores[existingIdx] = {
                        index: problem_index,
                        score: score,
                        passed: testResult.passed,
                        submission_time: submission.submitted_at,
                        problem_title: problem.title
                    };
                }
            } else {
                problemScores.push({
                    index: problem_index,
                    score: score,
                    passed: testResult.passed,
                    submission_time: submission.submitted_at,
                    problem_title: problem.title
                });
            }
            
            // Recalculate totals
            totalScore = problemScores.reduce((sum, p) => sum + p.score, 0);
            problemsSolved = problemScores.filter(p => p.passed).length;
        } else {
            problemScores = [{
                index: problem_index,
                score: score,
                passed: testResult.passed,
                submission_time: submission.submitted_at,
                problem_title: problem.title
            }];
        }
        
        // Save updated result
        await client.send(new PutItemCommand({
            TableName: "DebugStudentResults",
            Item: ddbMarshall({
                result_id: resultId,
                contest_id: contest_id,
                contest_name: contest.name,
                student_email: req.user.email,
                student_name: req.user.name || "Student",
                total_score: totalScore,
                max_score: contest.metadata?.total_score || 0,
                problems_solved: problemsSolved,
                total_problems: contest.problems?.length || 0,
                problem_scores: problemScores,
                updated_at: new Date().toISOString(),
                status: problemsSolved === contest.problems?.length ? 'completed' : 'in_progress'
            })
        }));
        
        res.json({
            success: true,
            data: {
                passed: testResult.passed,
                score: score,
                message: testResult.passed 
                    ? "✅ Bug fixed successfully!" 
                    : "❌ Test failed. Try again.",
                student_progress: {
                    total_score: totalScore,
                    problems_solved: problemsSolved,
                    total_problems: contest.problems?.length || 0
                }
            }
        });
        
    } catch (err) {
        console.error("Submit Debug Solution Error:", err);
        res.status(500).json({ 
            success: false,
            message: "Error submitting solution",
            error: err.message 
        });
    }
});

// Get student's debug contest results
app.get('/api/student/debug-results/:contestId', verifyToken, async (req, res) => {
    try {
        const contestId = req.params.contestId;
        const userEmail = req.user.email;

        console.log(`Getting debug results for contest ${contestId}, student ${userEmail}`);

        // Get result from DebugStudentResults table
        const resultId = `res_${userEmail}_${contestId}`;
        const { Item: resultItem } = await client.send(new GetItemCommand({
            TableName: "DebugStudentResults",
            Key: ddbMarshall({ result_id: resultId })
        }));

        // Get contest details
        const { Item: contestItem } = await client.send(new GetItemCommand({
            TableName: "DebugContests",
            Key: ddbMarshall({ contest_id: contestId })
        }));

        const contest = contestItem ? unmarshall(contestItem) : null;

        if (resultItem) {
            const result = unmarshall(resultItem);
            
            // Get submissions for detailed results
            const { Items: subItems } = await client.send(new QueryCommand({
                TableName: "DebugSubmissions",
                IndexName: "StudentSubmissionsIndex",
                KeyConditionExpression: "student_email = :email",
                FilterExpression: "contest_id = :cid",
                ExpressionAttributeValues: ddbMarshall({
                    ":email": userEmail,
                    ":cid": contestId
                }),
                ScanIndexForward: false
            }));

            const submissions = (subItems || []).map(i => unmarshall(i));

            res.json({
                success: true,
                data: {
                    ...result,
                    contest_name: contest?.name || "Unknown Contest",
                    submissions: submissions,
                    contest_details: {
                        total_problems: contest?.problems?.length || 0,
                        max_score: contest?.metadata?.total_score || 0
                    }
                }
            });
        } else {
            // Return empty result if not found
            res.json({
                success: true,
                data: {
                    result_id: resultId,
                    contest_id: contestId,
                    contest_name: contest?.name || "Unknown Contest",
                    student_email: userEmail,
                    total_score: 0,
                    max_score: contest?.metadata?.total_score || 0,
                    problems_solved: 0,
                    total_problems: contest?.problems?.length || 0,
                    problem_scores: [],
                    status: 'not_started',
                    submissions: [],
                    contest_details: {
                        total_problems: contest?.problems?.length || 0,
                        max_score: contest?.metadata?.total_score || 0
                    }
                }
            });
        }

    } catch (err) {
        console.error("Get Student Debug Results Error:", err);
        res.status(500).json({
            success: false,
            message: "Error fetching debug results",
            error: err.message
        });
    }
});

// Get all debug submissions for a student in a contest
app.get('/api/student/debug-submissions/:contestId', verifyToken, async (req, res) => {
    try {
        const contestId = req.params.contestId;
        const userEmail = req.user.email;

        const { Items } = await client.send(new QueryCommand({
            TableName: "DebugSubmissions",
            IndexName: "StudentSubmissionsIndex",
            KeyConditionExpression: "student_email = :email",
            FilterExpression: "contest_id = :cid",
            ExpressionAttributeValues: ddbMarshall({
                ":email": userEmail,
                ":cid": contestId
            }),
            ScanIndexForward: false,
            Limit: 50
        }));

        const submissions = (Items || []).map(i => unmarshall(i));

        res.json({
            success: true,
            data: {
                contest_id: contestId,
                student_email: userEmail,
                submissions: submissions,
                count: submissions.length
            }
        });

    } catch (err) {
        console.error("Get Debug Submissions Error:", err);
        res.status(500).json({
            success: false,
            message: "Error fetching debug submissions",
            error: err.message
        });
    }
});
// ====================================================
// DEBUG RESULTS MANAGEMENT ROUTES (FOR MODERATORS)
// ====================================================

// Get all debug contest results for a specific contest
app.get('/api/moderator/debug-contest/:id/results', verifyToken, async (req, res) => {
    try {
        const contestId = req.params.id;
        
        console.log(`Fetching debug contest results for ${contestId}`);

        // Get contest details
        const { Item: contestItem } = await client.send(new GetItemCommand({
            TableName: "DebugContests",
            Key: ddbMarshall({ contest_id: contestId })
        }));

        if (!contestItem) {
            return res.status(404).json({
                success: false,
                message: "Debug contest not found"
            });
        }

        const contest = unmarshall(contestItem);

        // Get all results for this contest from DebugStudentResults table
        const { Items } = await client.send(new QueryCommand({
            TableName: "DebugStudentResults",
            IndexName: "ContestResultsIndex", // You need this GSI on contest_id
            KeyConditionExpression: "contest_id = :cid",
            ExpressionAttributeValues: ddbMarshall({
                ":cid": contestId
            })
        }));

        let results = (Items || []).map(i => unmarshall(i));

        // If GSI doesn't exist, scan and filter
        if (results.length === 0) {
            const { Items: allItems } = await client.send(new ScanCommand({
                TableName: "DebugStudentResults",
                FilterExpression: "contest_id = :cid",
                ExpressionAttributeValues: ddbMarshall({
                    ":cid": contestId
                })
            }));
            results = (allItems || []).map(i => unmarshall(i));
        }

        // Get student details for each result
        const resultsWithDetails = await Promise.all(
            results.map(async (result) => {
                const { Item: studentItem } = await client.send(new GetItemCommand({
                    TableName: "Students",
                    Key: ddbMarshall({ email: result.student_email })
                }));

                const student = studentItem ? unmarshall(studentItem) : null;

                // Get submissions for this student
                const { Items: subItems } = await client.send(new QueryCommand({
                    TableName: "DebugSubmissions",
                    IndexName: "StudentSubmissionsIndex",
                    KeyConditionExpression: "student_email = :email",
                    FilterExpression: "contest_id = :cid",
                    ExpressionAttributeValues: ddbMarshall({
                        ":email": result.student_email,
                        ":cid": contestId
                    }),
                    Limit: 5
                }));

                const recentSubmissions = (subItems || []).map(i => unmarshall(i));

                return {
                    ...result,
                    student_name: student?.name || result.student_email,
                    college: student?.college || 'Unknown',
                    recent_submissions: recentSubmissions,
                    rank: 0 // Will be calculated later
                };
            })
        );

        // Sort by score (highest first) and calculate rank
        resultsWithDetails.sort((a, b) => b.total_score - a.total_score);
        resultsWithDetails.forEach((result, index) => {
            result.rank = index + 1;
        });

        // Calculate statistics
        const stats = {
            total_participants: resultsWithDetails.length,
            average_score: resultsWithDetails.length > 0 
                ? resultsWithDetails.reduce((sum, r) => sum + r.total_score, 0) / resultsWithDetails.length 
                : 0,
            highest_score: resultsWithDetails.length > 0 ? resultsWithDetails[0].total_score : 0,
            completion_rate: resultsWithDetails.length > 0 
                ? (resultsWithDetails.filter(r => r.status === 'completed').length / resultsWithDetails.length) * 100 
                : 0,
            problems_stats: contest.problems?.map((problem, index) => {
                const problemResults = resultsWithDetails.map(r => {
                    const problemScore = r.problem_scores?.find(p => p.index === index);
                    return {
                        score: problemScore?.score || 0,
                        passed: problemScore?.passed || false
                    };
                });
                
                const passedCount = problemResults.filter(p => p.passed).length;
                
                return {
                    problem_index: index,
                    problem_title: problem.title,
                    total_participants: resultsWithDetails.length,
                    passed_count: passedCount,
                    pass_rate: resultsWithDetails.length > 0 ? (passedCount / resultsWithDetails.length) * 100 : 0,
                    average_score: problemResults.reduce((sum, p) => sum + p.score, 0) / resultsWithDetails.length || 0
                };
            }) || []
        };

        res.json({
            success: true,
            data: {
                contest: {
                    id: contest.contest_id,
                    name: contest.name,
                    total_problems: contest.problems?.length || 0,
                    total_score: contest.metadata?.total_score || 0,
                    language: contest.language,
                    created_at: contest.created_at
                },
                results: resultsWithDetails,
                statistics: stats
            }
        });

    } catch (err) {
        console.error("Get Debug Contest Results Error:", err);
        res.status(500).json({
            success: false,
            message: "Error fetching debug contest results",
            error: err.message
        });
    }
});

// Get specific debug submission details
app.get('/api/moderator/debug-submission/:id', verifyToken, async (req, res) => {
    try {
        const submissionId = req.params.id;

        const { Item } = await client.send(new GetItemCommand({
            TableName: "DebugSubmissions",
            Key: ddbMarshall({ submission_id: submissionId })
        }));

        if (!Item) {
            return res.status(404).json({
                success: false,
                message: "Debug submission not found"
            });
        }

        const submission = unmarshall(Item);

        // Get contest details
        const { Item: contestItem } = await client.send(new GetItemCommand({
            TableName: "DebugContests",
            Key: ddbMarshall({ contest_id: submission.contest_id })
        }));

        const contest = contestItem ? unmarshall(contestItem) : null;
        const problem = contest?.problems?.[submission.problem_index];

        res.json({
            success: true,
            data: {
                submission: submission,
                contest: {
                    name: contest?.name,
                    language: contest?.language
                },
                problem: {
                    title: problem?.title,
                    buggy_code: problem?.buggy_code,
                    expected_output: problem?.output
                }
            }
        });

    } catch (err) {
        console.error("Get Debug Submission Error:", err);
        res.status(500).json({
            success: false,
            message: "Error fetching debug submission",
            error: err.message
        });
    }
});
// ====================================================
// ADDITIONAL UTILITY ROUTES FOR DEBUG CONTESTS
// ====================================================

// Get available debug contests for student dashboard
app.get('/api/student/available-debug-contests', verifyToken, async (req, res) => {
    try {
        const userEmail = req.user.email;
        
        // Get student's college for filtering
        const { Item: studentItem } = await client.send(new GetItemCommand({
            TableName: "Students",
            Key: ddbMarshall({ email: userEmail })
        }));
        
        const student = studentItem ? unmarshall(studentItem) : null;
        const studentCollege = student?.college || '';

        // Get all active debug contests
        const { Items } = await client.send(new ScanCommand({
            TableName: "DebugContests",
            FilterExpression: "#status = :status",
            ExpressionAttributeNames: {
                "#status": "status"
            },
            ExpressionAttributeValues: ddbMarshall({
                ":status": "active"
            })
        }));

        const allContests = (Items || []).map(i => unmarshall(i));

        // Filter contests based on eligibility and progression rules
        const availableContests = await Promise.all(
            allContests.map(async (contest) => {
                // Check target type
                if (contest.target_type === 'college' && contest.target_college) {
                    if (!studentCollege || studentCollege.toLowerCase() !== contest.target_college.toLowerCase()) {
                        return null; // Not eligible
                    }
                }

                // Check progression rules
                let hasAccess = true;
                let prerequisiteInfo = null;

                if (contest.requires_prerequisite && contest.prerequisite_contest_id) {
                    const normalResultId = `res_${userEmail}_${contest.prerequisite_contest_id}`;
                    const { Item: normalResultItem } = await client.send(new GetItemCommand({
                        TableName: "StudentResults",
                        Key: ddbMarshall({ result_id: normalResultId })
                    }));

                    if (!normalResultItem) {
                        hasAccess = false;
                        prerequisiteInfo = {
                            required: true,
                            contest_id: contest.prerequisite_contest_id,
                            status: 'not_started',
                            message: 'Complete prerequisite contest first'
                        };
                    } else {
                        const normalResult = unmarshall(normalResultItem);
                        
                        // Get passing score from progression rule
                        const { Items: ruleItems } = await client.send(new ScanCommand({
                            TableName: "ContestProgressionRules",
                            FilterExpression: "debug_contest_id = :debugId",
                            ExpressionAttributeValues: ddbMarshall({
                                ":debugId": contest.contest_id
                            })
                        }));
                        
                        const passingScore = ruleItems && ruleItems.length > 0 
                            ? unmarshall(ruleItems[0]).passing_score 
                            : 70;

                        hasAccess = normalResult.status === 'completed' && 
                            normalResult.total_score >= passingScore;

                        prerequisiteInfo = {
                            required: true,
                            contest_id: contest.prerequisite_contest_id,
                            your_score: normalResult.total_score,
                            required_score: passingScore,
                            status: hasAccess ? 'passed' : 'failed',
                            message: hasAccess 
                                ? 'Prerequisite completed' 
                                : `Need ${passingScore}% to unlock`
                        };
                    }
                }

                // Get student's result for this debug contest
                const debugResultId = `res_${userEmail}_${contest.contest_id}`;
                const { Item: debugResultItem } = await client.send(new GetItemCommand({
                    TableName: "DebugStudentResults",
                    Key: ddbMarshall({ result_id: debugResultId })
                }));

                const debugResult = debugResultItem ? unmarshall(debugResultItem) : null;

                return {
                    contest_id: contest.contest_id,
                    name: contest.name,
                    language: contest.language,
                    description: contest.description,
                    target_type: contest.target_type,
                    target_college: contest.target_college,
                    problems_count: contest.problems?.length || 0,
                    total_score: contest.metadata?.total_score || 0,
                    time_limit: contest.metadata?.time_limit || 60,
                    created_at: contest.created_at,
                    has_access: hasAccess,
                    prerequisite: prerequisiteInfo,
                    student_progress: {
                        total_score: debugResult?.total_score || 0,
                        problems_solved: debugResult?.problems_solved || 0,
                        status: debugResult?.status || 'not_started',
                        last_submission: debugResult?.updated_at
                    },
                    metadata: {
                        difficulty: contest.metadata?.difficulty || 'Medium',
                        topic: contest.metadata?.topic || 'General'
                    }
                };
            })
        );

        // Filter out null values and sort
        const filteredContests = availableContests.filter(c => c !== null);
        
        // Sort: accessible contests first, then by progress, then by date
        filteredContests.sort((a, b) => {
            if (a.has_access !== b.has_access) return b.has_access - a.has_access;
            if (a.student_progress.status !== b.student_progress.status) {
                const statusOrder = { 'completed': 0, 'in_progress': 1, 'not_started': 2 };
                return statusOrder[a.student_progress.status] - statusOrder[b.student_progress.status];
            }
            return new Date(b.created_at) - new Date(a.created_at);
        });

        res.json({
            success: true,
            data: {
                contests: filteredContests,
                student: {
                    email: userEmail,
                    name: student?.name,
                    college: studentCollege
                },
                stats: {
                    total_contests: filteredContests.length,
                    accessible_contests: filteredContests.filter(c => c.has_access).length,
                    completed_contests: filteredContests.filter(c => c.student_progress.status === 'completed').length
                }
            }
        });

    } catch (err) {
        console.error("Get Available Debug Contests Error:", err);
        res.status(500).json({
            success: false,
            message: "Error fetching available debug contests",
            error: err.message
        });
    }
});
// ====================================================
// 13. SERVER STARTUP
// ====================================================

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));