const express = require('express');
const cors = require('cors');
const axios = require('axios');
const fs = require('fs');
const csv = require('csv-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cron = require('node-cron');
const { format } = require('@fast-csv/format');
const { Pool } = require('pg');
require('dotenv').config({ path: './tnd.env' });

const app = express();
const port = 8000;

app.use(cors());
app.use(express.json());

//secret key for jwt token
const secretKey = process.env.SECRET_KEY;

//initializing postgres database user config
const dbConfig = {
    app_user: {
        user: process.env.APP_USER,
        host: process.env.DB_HOST,
        database: process.env.DB_NAME,
        password: process.env.APP_USER_PASSWORD,
        port: process.env.DB_PORT,
    },
    admin_user: {
        user: process.env.ADMIN_USER,
        host: process.env.DB_HOST,
        database: process.env.DB_NAME,
        password: process.env.ADMIN_USER_PASSWORD,
        port: process.env.DB_PORT,
    }
}

//Helper function to connect to the postgres database based on role (admin or user)
function getDBConnection(role) {
    if(role === 'admin_user') {
        return new Pool(dbConfig.admin_user);
    } else {
        return new Pool(dbConfig.app_user);
    }
}
//helper function that verifies if the session token is valid
async function verifySession(req) {
    const pool = getDBConnection('admin_user');

    let token;

    // Check if the token is provided in headers or query string
    if (req.headers && req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
        token = req.headers.authorization.split(' ')[1];
    } else if (req.query && req.query.token) {
        token = req.query.token;
    }

    if (!token) {
        console.error('Token not provided');
        return false; // Return false if no token is provided
    }

    try {
        // Verify the token against the database
        const client = await pool.connect();
        const query = `
            SELECT * FROM tblSessions 
            LEFT JOIN tblUsers ON tblSessions.UserID = tblUsers.UserID 
            WHERE tblSessions.SessionToken = $1;
        `;
        const res = await client.query(query, [token]);
        client.release();
        return res.rows.length > 0 ? res.rows[0] : false;
    } catch (err) {
        console.error('Error verifying session:', err);
        return false;
    }
}


//helper function that checks if the session token is valid
async function checkSessionInDB(pool, token) {
    try {
        const client = await pool.connect();
        const query = `
            SELECT * FROM tblSessions 
            LEFT JOIN tblUsers ON tblSessions.UserID = tblUsers.UserID 
            WHERE tblSessions.SessionToken = $1;
        `;
        const res = await client.query(query, [token]);
        client.release();
        return res.rows.length > 0 ? res.rows[0] : false;
    } catch (err) {
        console.error('Error verifying session', err);
        return false;
    }
}


//Helper function to extract relevant data
const extractRelevantData = (responseData) => {

    const facilityInfo = responseData.Results.FacilityInfo || {};

    //The data to be extracted
    const extractedData = {
        FacilityDesignFlow: facilityInfo.FacilityDesignFlow || null,
        ActualAvgFacilityFlow: facilityInfo.ActualAvgFacilityFlow || null,
        AvgFacilityFlow: facilityInfo.AvgFacilityFlow || null,
        Nitrogen: {},
        Phosphorus: {},
    };

    //Extracting relevant data from TopPollutantPounds
    responseData.Results.TopPollutantPounds?.forEach((item) => {
        if (item.PollutantName === 'Nitrogen') {
            extractedData.Nitrogen = {
                TotalPounds: item.TotalPounds || null,
                MaxAllowablePounds: item.MaxAllowable || null,
            };
        }
        if (item.PollutantName === 'Phosphorus') {
            extractedData.Phosphorus = {
                TotalPounds: item.TotalPounds || null,
                MaxAllowablePounds: item.MaxAllowable || null,
            };
        }
    });

    return extractedData;
};


//Helper function to fetch data with retry logic included in case of server errors
const fetchDataWithRetry = async (url, retries, delay) => {
    let attempt = 0;
    while (attempt <= retries) {
        try {
            const response = await axios.get(url);
            return response.data;
        } catch (error) {
            if (attempt < retries && error.response && error.response.status === 503) {
                console.log(`Retrying... (${retries - attempt} attempts left)`);
                await new Promise((resolve) => setTimeout(resolve, delay));
                attempt++;
            } else {
                throw error;
            }
        }
    }
};
//Helper function to insert data into the postgres database
const insertData = async (db, data) => { 
    const query = `
        INSERT INTO nutrient_data 
        (permit_number, year, facility_name, facility_design_flow, actual_avg_facility_flow, avg_facility_flow, 
         nitrogen_total_pounds, nitrogen_max_allowable_pounds, 
         phosphorus_total_pounds, phosphorus_max_allowable_pounds) 
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        ON CONFLICT (permit_number, year) DO UPDATE SET
            facility_name = EXCLUDED.facility_name,
            facility_design_flow = EXCLUDED.facility_design_flow,
            actual_avg_facility_flow = EXCLUDED.actual_avg_facility_flow,
            avg_facility_flow = EXCLUDED.avg_facility_flow,
            nitrogen_total_pounds = EXCLUDED.nitrogen_total_pounds,
            nitrogen_max_allowable_pounds = EXCLUDED.nitrogen_max_allowable_pounds,
            phosphorus_total_pounds = EXCLUDED.phosphorus_total_pounds,
            phosphorus_max_allowable_pounds = EXCLUDED.phosphorus_max_allowable_pounds;
    `;

    try {
        for (const row of data) {
            const facilityData = row.Data || {};
            const nitrogenData = facilityData.Nitrogen || {};
            const phosphorusData = facilityData.Phosphorus || {};

            // Run the query with parameterized values
            await db.query(query, [
                row.permitNumber,
                row.year,
                row.facilityName || null,
                facilityData.FacilityDesignFlow || null,
                facilityData.ActualAvgFacilityFlow || null,
                facilityData.AvgFacilityFlow || null,
                nitrogenData.TotalPounds || null,
                nitrogenData.MaxAllowablePounds || null,
                phosphorusData.TotalPounds || null,
                phosphorusData.MaxAllowablePounds || null,
            ]);
        }
    } catch (error) {
        console.error('Error inserting/updating data:', error);
        throw error; // Optionally, re-throw the error to handle it later
    }
};



//Helper function to query data from a specific year
const queryDataByYear = async (db, year) => {
    let query;
    let params = [];

    if (year === 'ALL') {
        query = `SELECT * FROM nutrient_data`;
    } else {
        query = `SELECT * FROM nutrient_data WHERE year = $1`;
        params = [year];
    }

    try {
        const res = await db.query(query, params); // Use the provided db connection
        return res.rows;
    } catch (err) {
        console.error(err);
        throw err;
    }
};

//Helper function to fetch the data from tblTier1 - 3 depending on the input (1-3)
const fetchTierData = async (db, tier) => {
    try {
        const query = `SELECT * FROM tblTier${tier}`;
        const res = await db.query(query);
        return res.rows;
    } catch (err) {
        console.error(err);
        throw err;
    }
};


// Endpoint to fetch and store data into an postgres database
app.get('/api/nutrient-data', async (req, res) => {
    try {
        // Extract the token from query parameters
        const token = req.query.token;

        // Verify the session
        const isSessionValid = await verifySession({ query: { token } });
        if (!isSessionValid) {
            return res.status(401).json({ error: 'Invalid or expired session' });
        }

        const { year } = req.query;
        if (!year) {
            return res.status(400).json({ error: 'Year is required' });
        }

        const data = [];
        const rowsFromCSV = [];

        // Set headers for SSE
        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Connection', 'keep-alive');
        res.flushHeaders(); // Ensure headers are sent immediately

        // Read CSV rows
        fs.createReadStream('Data(N&P Data for Mech WWTP).csv')
            .pipe(csv())
            .on('data', (row) => {
                rowsFromCSV.push(row);
            })
            .on('end', async () => {
                console.log(`Total rows read from CSV: ${rowsFromCSV.length}`);

                let processedCount = 0;
                const totalToProcess = Math.ceil(rowsFromCSV.length / 2);

                for (let i = 0; i < rowsFromCSV.length; i += 2) {
                    const row = rowsFromCSV[i];
                    const permitNumber = row['Permit Number'];
                    const permitName = row['Permittee Name'];
                    const api_url = `https://echodata.epa.gov/echo/dmr_rest_services.get_facility_report?output=JSON&p_permit_id=${permitNumber}&p_year=${year}`;

                    console.log(`Fetching data for Permit Number: ${permitNumber} (${processedCount + 1}/${totalToProcess})`);

                    try {
                        const apiResponse = await fetchDataWithRetry(api_url, 3, 1000); // 1-second delay
                        const extractedData = extractRelevantData(apiResponse);

                        data.push({
                            permitNumber,
                            facilityName: permitName,
                            year,
                            Data: extractedData,
                        });
                    } catch (error) {
                        console.error(`Error fetching data for Permit Number ${permitNumber}:`, error.message);
                        data.push({
                            permitNumber,
                            facilityName: permitName,
                            year,
                            Data: null,
                        });
                    }

                    processedCount++;

                    // Send progress update to the client
                    const progress = ((processedCount / totalToProcess) * 100).toFixed(2);
                    console.log(`Sending progress: ${progress}%`);  // Debugging log
                    res.write(`data: ${JSON.stringify({ progress })}\n\n`);
                }

                console.log(`Total rows processed: ${data.length}`);

                const db = getDBConnection('admin_user');
                try {
                    await insertData(db, data);
                    res.write(`data: ${JSON.stringify({ message: 'Data fetched and stored successfully!' })}\n\n`);
                } catch (error) {
                    console.error('Error inserting data into database:', error);
                    res.write(`data: ${JSON.stringify({ error: 'Failed to store data in the database' })}\n\n`);
                } finally {
                    db.end();
                }

                // End the SSE stream
                res.end();
            });
    } catch (err) {
        console.error('Session verification error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});




// Endpoint to download data in CSV format
app.get('/api/download-data', async (req, res) => {
    try {
        // Verify the session before proceeding
        const isSessionValid = await verifySession(req);
        if (!isSessionValid) {
            return res.status(401).json({ error: 'Invalid or expired session' });
        }

        const { year } = req.query; // Year given by the user for this call
        const db = getDBConnection('app_user');

        // Error handling if no year is sent
        if (!year) {
            return res.status(400).json({ error: 'Year is required' });
        }

        // Using the query by year function to get data
        const rows = await queryDataByYear(db, year);

        if (rows.length === 0) {
            return res.status(404).json({ error: 'No data found for the specified year' });
        }

        // Creating the file stream here
        const filePath = `./data_${year}.csv`;
        const writableStream = fs.createWriteStream(filePath);
        const csvStream = format({ headers: true });

        csvStream.pipe(writableStream);

        // Write the rows to the CSV
        rows.forEach(row => {
            csvStream.write(row);
        });

        csvStream.end();

        // Finishing up
        writableStream.on('finish', () => {
            // Sending the file as a download
            res.download(filePath, `data_${year}.csv`, (err) => {
                if (err) {
                    console.error('Error sending file:', err);
                }
                // Deleting the file after sending to the user
                fs.unlinkSync(filePath);
            });
        });
    } catch (err) {
        console.error('Error querying data:', err);
        return res.status(500).json({ error: 'Database query error' });
    }
});



// Endpoint to grab data by year from the PostgreSQL database
app.get('/api/grab-db-data', async (req, res) => {
    try {
        // Verify the session before proceeding
        const isSessionValid = await verifySession(req);
        if (!isSessionValid) {
            return res.status(401).json({ error: 'Invalid or expired session' });
        }

        const { year } = req.query;

        // Error handling if no year is sent
        if (!year) {
            return res.status(400).json({ error: 'Year is required' });
        }

        // Define the query and parameters based on the value of year
        let query;
        let params = [];
        const db = getDBConnection('app_user');

        if (year === 'ALL') {
            // Fetch all data if year is 'ALL'
            query = `SELECT * FROM nutrient_data`;
        } else {
            // Fetch data for the specific year, using $1 for parameterized query
            query = `SELECT * FROM nutrient_data WHERE year = $1`;
            params = [year];
        }

        // Query the PostgreSQL database using the chosen query and parameters
        const result = await db.query(query, params);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'No data found' });
        }

        // Return the data as JSON
        res.json(result.rows);
    } catch (err) {
        console.error('Database query error:', err);
        return res.status(500).json({ error: 'Database query error' });
    }
});



//Endpoint to check if new data exists in the EPA ECHO database and fetch it for all permits
app.get('/api/check-new-data', (req, res) => {
    const { year } = req.query;

    //Error handling
    if (!year) {
        return res.status(400).json({ error: 'Year is required' });
    }

    //Fetching all permit numbers from the SQLite database
    const getPermitNumbersQuery = `SELECT DISTINCT permit_number FROM nutrient_data`;

    db.all(getPermitNumbersQuery, [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Database error while fetching permit numbers' });
        }

        if (rows.length === 0) {
            return res.status(404).json({ error: 'No permit numbers found in the database' });
        }

        //Sequentially process each permit number using recursion
        const processPermitNumbers = (index) => {
            if (index >= rows.length) {
                // Finished processing all permits
                return res.json({ status: true, message: 'All permit data checked and updated if new data found.' });
            }

            const permitNumber = rows[index].permit_number;
            const api_url = `https://echodata.epa.gov/echo/dmr_rest_services.get_facility_report?output=JSON&p_permit_id=${permitNumber}&p_year=${year}`;

            //Fetch data from the EPA ECHO API
            axios.get(api_url)
                .then(response => {
                    const newData = response.data;

                    if (newData && newData.Results) {
                        console.log(`Found new data for permit ${permitNumber} for year ${year}`);

                        // Fetch the existing data for this permit and year
                        const selectQuery = `SELECT * FROM nutrient_data WHERE permit_number = ? AND year = ?`;
                        db.get(selectQuery, [permitNumber, year], (err, existingData) => {
                            if (err) {
                                console.error(`Error fetching existing data for permit ${permitNumber}:`, err);
                                // Process the next permit number
                                return processPermitNumbers(index + 1);
                            }

                            // If there's no existing record, we will insert the new data directly
                            if (!existingData) {
                                const insertStmt = db.prepare(`
                                    INSERT INTO nutrient_data (
                                        year, permit_number, facility_name, facility_design_flow, 
                                        actual_avg_facility_flow, avg_facility_flow, nitrogen_total_pounds, 
                                        nitrogen_max_allowable_pounds, phosphorus_total_pounds, phosphorus_max_allowable_pounds
                                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                `);

                                const facilityInfo = newData.Results.FacilityInfo || {};
                                const nitrogen = newData.Results.PollutantLoads.find(p => p.PollutantName === 'Nitrogen') || {};
                                const phosphorus = newData.Results.PollutantLoads.find(p => p.PollutantName === 'Phosphorus') || {};

                                insertStmt.run(
                                    year,
                                    permitNumber,
                                    facilityInfo.FacilityName || null,
                                    parseFloat(facilityInfo.FacilityDesignFlow) || null,
                                    parseFloat(facilityInfo.ActualAvgFacilityFlow) || null,
                                    parseFloat(facilityInfo.AvgFacilityFlow) || null,
                                    parseFloat(nitrogen.TotalPounds) || null,
                                    parseFloat(nitrogen.MaxAllowablePounds) || null,
                                    parseFloat(phosphorus.TotalPounds) || null,
                                    parseFloat(phosphorus.MaxAllowablePounds) || null
                                );
                                insertStmt.finalize();
                            } else {
                                // Update only fields that are NULL in the database
                                const updateStmt = db.prepare(`
                                    UPDATE nutrient_data
                                    SET 
                                        facility_name = COALESCE(?, facility_name),
                                        facility_design_flow = COALESCE(?, facility_design_flow),
                                        actual_avg_facility_flow = COALESCE(?, actual_avg_facility_flow),
                                        avg_facility_flow = COALESCE(?, avg_facility_flow),
                                        nitrogen_total_pounds = COALESCE(?, nitrogen_total_pounds),
                                        nitrogen_max_allowable_pounds = COALESCE(?, nitrogen_max_allowable_pounds),
                                        phosphorus_total_pounds = COALESCE(?, phosphorus_total_pounds),
                                        phosphorus_max_allowable_pounds = COALESCE(?, phosphorus_max_allowable_pounds)
                                    WHERE year = ? AND permit_number = ?
                                `);

                                const facilityInfo = newData.Results.FacilityInfo || {};
                                const nitrogen = newData.Results.PollutantLoads.find(p => p.PollutantName === 'Nitrogen') || {};
                                const phosphorus = newData.Results.PollutantLoads.find(p => p.PollutantName === 'Phosphorus') || {};

                                updateStmt.run(
                                    facilityInfo.FacilityName || null,
                                    parseFloat(facilityInfo.FacilityDesignFlow) || null,
                                    parseFloat(facilityInfo.ActualAvgFacilityFlow) || null,
                                    parseFloat(facilityInfo.AvgFacilityFlow) || null,
                                    parseFloat(nitrogen.TotalPounds) || null,
                                    parseFloat(nitrogen.MaxAllowablePounds) || null,
                                    parseFloat(phosphorus.TotalPounds) || null,
                                    parseFloat(phosphorus.MaxAllowablePounds) || null,
                                    year,
                                    permitNumber
                                );
                                updateStmt.finalize();
                            }

                            // Process the next permit number
                            processPermitNumbers(index + 1);
                        });
                    } else {
                        console.log(`No new data found for permit ${permitNumber} for year ${year}`);
                        // Process the next permit number
                        processPermitNumbers(index + 1);
                    }
                })
                .catch(error => {
                    console.error(`Error fetching data for permit ${permitNumber}:`, error.message);
                    // Process the next permit number, even if there's an error
                    processPermitNumbers(index + 1);
                });
        };

        // Start processing permits from the first one
        processPermitNumbers(0);
    });
});

//endpoint for user registration here, will make sure that the email is not already in the postgres database and that the passwords match
app.post('/api/register', async (req, res) => {
    const { password, email } = req.body; 
    const pool = getDBConnection('admin_user');

    if (!password || !email) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    try {
        //Check if the email already exists
        const userCheck = await pool.query(
            'SELECT * FROM tblusers WHERE email = $1',
            [email]
        );

        if (userCheck.rows.length > 0) {
            res.status(400).json({ error: 'Email already in use' });
            return;
        }

        //Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        //Insert the new user into tblusers with the 'app_user' role
        await pool.query(
            'INSERT INTO tblusers (email, passwordhash, role) VALUES ($1, $2, $3)',
            [email, hashedPassword, 'app_user']
        );

        res.status(201).json({ message: 'User registered successfully!' });
    } catch (err) {
        console.error('Database error:', err);
        res.status(500).json({ error: 'Internal server error.' });
    }
});


//login endpoint
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const pool = getDBConnection('admin_user');

    try {
        // Retrieve user from the database
        const userResult = await pool.query('SELECT userid, passwordhash, role FROM tblusers WHERE email = $1', [email]);
        const user = userResult.rows[0];

        if (!user) {
            return res.status(401).json({ error: 'User not found' });
        }

        // Compare provided password with hashed password in the database
        const passwordMatch = await bcrypt.compare(password, user.passwordhash);

        if (passwordMatch) {
            const token = jwt.sign(
                { userId: user.userid, email: email, role: user.role },
                secretKey,
                { expiresIn: '1h' } // Token expires in 1 hour
            );

            const expirationTime = new Date(Date.now() + 3600000);

            // Insert the session into tblSessions
            await pool.query(
                `INSERT INTO tblSessions (userid, sessiontoken, createdat, expiration_time)
                 VALUES ($1, $2, NOW(), $3)`,
                [user.userid, token, expirationTime]
            );

            return res.status(200).json({ message: 'Login successful', token: token });
        } else {
            return res.status(401).json({ error: 'Invalid password' });
        }
    } catch (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
});


//scheduling a job every hour to clean up the sessions table in the database
cron.schedule('0 * * * *', async () => {
    try {
        //Variable for the current time
        const now = new Date();

        const pool = getDBConnection('admin_user');

        //Deleting expired sessions from the database
        await pool.query(`DELETE FROM tblSessions WHERE expiration_time < $1`, [now]);
        console.log('Expired sessions cleaned up.');
    } catch (err) {
        console.error('Error cleaning up expired sessions', err);
    }
});

//logout endpoint
app.post('/api/logout', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1]; 
    
    if (!token) {
        return res.status(400).json({ error: 'Token is required for logout' });
    }

    const pool = getDBConnection('admin_user');
    try {
        const deleteQuery = `DELETE FROM tblSessions WHERE sessiontoken = $1`;
        await pool.query(deleteQuery, [token]);
        res.status(200).json({ message: 'Logged out successfully' });
    } catch (err) {
        console.error('Error during logout:', err);
        res.status(500).json({ error: 'Failed to log out' });
    }
});

//endpoint to verify token
app.get('/api/verify-token', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'Token is required' });
    }

    try {
        const session = await checkSessionInDB(getDBConnection('admin_user'), token);
        if (!session) {
            return res.status(401).json({ error: 'Invalid or expired token' });
        }
        res.status(200).json({ message: 'Token is valid' });
    } catch (error) {
        console.error('Token verification error:', error);
        res.status(500).json({ error: 'Failed to verify token' });
    }
});

//endpoint for admin to input data for various tiers
app.post('/api/document-tier-data', async (req, res) => {
    try {
        // Verify admin session
        const session = await verifySession(req);
        if (!session || session.role !== 'admin_user') {
            return res.status(403).json({ error: 'Access Denied: Admins only' });
        }

        const { tier, sector, metric, info } = req.body;

        // Validate input
        if (!tier || !sector || !metric || !info) {
            console.log('Validation failed:', { tier, sector, metric, info });
            return res.status(400).json({ error: 'All fields (tier, sector, metric, info) are required.' });
        }

        // Map tier to the correct table with quotes
        const tableName = `"tblTier${tier}"`;
        if (!['"tblTier1"', '"tblTier2"', '"tblTier3"'].includes(tableName)) {
            console.log('Invalid tier specified:', tier);
            return res.status(400).json({ error: 'Invalid tier specified.' });
        }

        // Build query dynamically based on the sector
        const query = `
            INSERT INTO ${tableName} (metric, ${sector})
            VALUES ($1, $2)
            ON CONFLICT (metric) DO UPDATE
            SET ${sector} = EXCLUDED.${sector};
        `;

        console.log('Executing query:', query, 'with values:', [metric, info]);

        // Execute query
        const pool = getDBConnection('admin_user');
        await pool.query(query, [metric, info]);

        res.status(200).json({ message: `Tier data for Tier ${tier}, Sector ${sector} saved successfully.` });
    } catch (error) {
        console.error('Error saving tier data:', error);
        res.status(500).json({ error: 'Failed to save tier data.' });
    }
});

//endpoint to verify role
app.get('/api/verify-user-role', async (req, res) => {
    try {
        const session = await verifySession(req);
        if (!session) {
            return res.status(401).json({ error: 'Unauthorized' });
        }
        res.status(200).json({ role: session.role });
    } catch (error) {
        console.error('Error verifying user role:', error);
        res.status(500).json({ error: 'Failed to verify user role' });
    }
});

//endpoint to grab tier data (1, 2, 3)
app.get('/api/tier-data', async (req, res) => {
    try {
        const session = await verifySession(req);
        if (!session) {
            return res.status(401).json({ error: 'Unauthorized' });
        }
        const tier = req.query.tier;
        const pool = getDBConnection(session.role);
        const data = await fetchTierData(pool, tier);
        res.status(200).json(data);
    } catch (error) {
        console.error('Error fetching tier data:', error);
        res.status(500).json({ error: 'Failed to fetch tier data' });
    }
});




//Start server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
