const express = require('express');
const { exec } = require('child_process');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const FLAG = process.env.FLAG || 'offsec{test}';
const QR_DIR = '/tmp/qrcodes';

if (!fs.existsSync(QR_DIR)) {
  fs.mkdirSync(QR_DIR, { recursive: true });
}

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'views'));
app.use(express.static(path.join(__dirname, '..', 'public')));
app.use(express.urlencoded({ extended: false }));

app.get('/', (req, res) => {
  res.render('index', { qrImage: null, error: null, url: '' });
});

app.post('/generate', (req, res) => {
  const url = req.body.url || '';

  if (!url.trim()) {
    return res.render('index', { qrImage: null, error: 'Please enter a URL to encode.', url });
  }

  if (url.length > 2048) {
    return res.render('index', { qrImage: null, error: 'URL exceeds maximum length (2048 chars).', url });
  }

  const filename = `${uuidv4()}.png`;
  const outputPath = path.join(QR_DIR, filename);

  const cmd = `qrencode -t PNG -o ${outputPath} -s 8 -m 2 '${url}'`;

  exec(cmd, { timeout: 5000 }, (error, stdout, stderr) => {
    if (error) {
      return res.render('index', {
        qrImage: null,
        error: 'Could not generate QR code. Please check your URL and try again.',
        url,
      });
    }

    res.render('index', { qrImage: `/qr/${filename}`, error: null, url });
  });
});

app.get('/qr/:filename', (req, res) => {
  const filename = req.params.filename;
  if (!/^[a-f0-9\-]+\.png$/.test(filename)) {
    return res.status(400).send('Nope.');
  }
  const filePath = path.join(QR_DIR, filename);
  if (!fs.existsSync(filePath)) {
    return res.status(404).send('File not found.');
  }
  res.sendFile(filePath);
});

app.use((req, res) => {
  res.status(404).render('404');
});

app.listen(PORT, () => {
  console.log(`QRDrop live on http://localhost:${PORT}`);
});
