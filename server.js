const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { exec } = require('child_process');

const app = express();
const PORT = process.env.PORT || 3000;

// Ensure directories exist inside workspace
const uploadsDir = path.join(__dirname, 'temp_uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// Config Multer for storage
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadsDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    fileFilter: (req, file, cb) => {
        // Accept only .pcap files
        const ext = path.extname(file.originalname).toLowerCase();
        if (ext === '.pcap') {
            cb(null, true);
        } else {
            cb(new Error('Only .pcap files are allowed'));
        }
    }
});

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Upload endpoint
app.post('/api/upload', upload.single('pcap'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded or invalid file type' });
    }
    
    res.json({
        message: 'File uploaded successfully',
        filename: req.file.filename,
        originalName: req.file.originalname,
        size: req.file.size
    });
});

// Run DPI engine analysis
app.post('/api/analyze', (req, res) => {
    const { filename, rules } = req.body;
    
    if (!filename) {
        return res.status(400).json({ error: 'Filename is required' });
    }
    
    const inputPath = path.join(uploadsDir, filename);
    if (!fs.existsSync(inputPath)) {
        return res.status(404).json({ error: 'Uploaded file not found' });
    }
    
    const outputFilename = 'filtered-' + filename;
    const outputPath = path.join(uploadsDir, outputFilename);
    const reportPath = path.join(uploadsDir, 'report-' + filename + '.json');
    
    // Build python execution command
    let cmd = `python "${path.join(__dirname, 'dpi_engine.py')}" "${inputPath}" "${outputPath}" --json-report "${reportPath}"`;
    
    if (rules) {
        if (Array.isArray(rules.blockedIps)) {
            rules.blockedIps.forEach(ip => {
                if (ip.trim()) cmd += ` --block-ip "${ip.trim()}"`;
            });
        }
        if (Array.isArray(rules.blockedApps)) {
            rules.blockedApps.forEach(app => {
                if (app.trim()) cmd += ` --block-app "${app.trim()}"`;
            });
        }
        if (Array.isArray(rules.blockedDomains)) {
            rules.blockedDomains.forEach(domain => {
                if (domain.trim()) cmd += ` --block-domain "${domain.trim()}"`;
            });
        }
    }
    
    console.log(`Executing: ${cmd}`);
    
    exec(cmd, (error, stdout, stderr) => {
        if (error) {
            console.error(`DPI Engine error: ${error.message}`);
            return res.status(500).json({ error: 'Failed to execute analysis engine', details: stderr });
        }
        
        // Read JSON report
        fs.readFile(reportPath, 'utf8', (err, data) => {
            if (err) {
                console.error(`Failed to read report: ${err.message}`);
                return res.status(500).json({ error: 'Failed to generate analysis report' });
            }
            
            try {
                const reportObj = JSON.parse(data);
                reportObj.filteredFilename = outputFilename; // save for download reference
                res.json(reportObj);
            } catch (parseErr) {
                res.status(500).json({ error: 'Failed to parse engine output report' });
            }
        });
    });
});

// Download filtered file
app.get('/api/download/:filename', (req, res) => {
    const filename = req.params.filename;
    // Prevent directory traversal attacks
    const safeFilename = path.basename(filename);
    const filePath = path.join(uploadsDir, safeFilename);
    
    if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: 'Filtered file not found' });
    }
    
    res.download(filePath, 'filtered_capture.pcap', (err) => {
        if (err) {
            console.error(`Download error: ${err.message}`);
        }
    });
});

// Generate simulated PCAP
app.post('/api/generate', (req, res) => {
    const { params } = req.body;
    
    if (!params) {
        return res.status(400).json({ error: 'Simulation parameters are required' });
    }
    
    const generatedFilename = `generated-${Date.now()}.pcap`;
    const outputPath = path.join(uploadsDir, generatedFilename);
    
    let cmd = `python "${path.join(__dirname, 'pcap_generator_helper.py')}" --output "${outputPath}"`;
    
    if (params.dns) cmd += ` --dns ${parseInt(params.dns)}`;
    if (params.http) cmd += ` --http ${parseInt(params.http)}`;
    if (params.blocked_ip_packets) cmd += ` --blocked-ip-packets ${parseInt(params.blocked_ip_packets)}`;
    
    if (params.apps) {
        Object.keys(params.apps).forEach(app => {
            const count = parseInt(params.apps[app]);
            if (count > 0) {
                cmd += ` --app-${app.toLowerCase()} ${count}`;
            }
        });
    }
    
    console.log(`Executing generator: ${cmd}`);
    
    exec(cmd, (error, stdout, stderr) => {
        if (error) {
            console.error(`Generator error: ${error.message}`);
            return res.status(500).json({ error: 'Failed to generate traffic capture', details: stderr });
        }
        
        res.json({
            message: 'Traffic capture generated successfully',
            filename: generatedFilename,
            size: fs.statSync(outputPath).size
        });
    });
});

// Cleanup temp files endpoint
app.post('/api/cleanup', (req, res) => {
    fs.readdir(uploadsDir, (err, files) => {
        if (err) return res.status(500).json({ error: 'Failed to list uploads directory' });
        
        let count = 0;
        files.forEach(file => {
            fs.unlinkSync(path.join(uploadsDir, file));
            count++;
        });
        
        res.json({ message: `Successfully deleted ${count} temporary files.` });
    });
});

// Start Server
app.listen(PORT, () => {
    console.log(`DeepInsight Dashboard running at http://localhost:${PORT}`);
});
