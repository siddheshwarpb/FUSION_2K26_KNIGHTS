const express = require('express');
const _ = require('lodash');

const app = express();
const port = 3000;

app.get('/health', (req, res) => {
  res.json({ status: 'healthy', version: '1.0.0' });
});

app.get('/api/merge', (req, res) => {
  const defaults = { role: 'guest', permissions: ['read'] };
  const user = req.query.user ? JSON.parse(req.query.user) : {};
  const result = _.merge({}, defaults, user);
  res.json({ user: result });
});

if (require.main === module) {
  app.listen(port, () => {
    console.log(`Demo app listening on port ${port}`);
  });
}

module.exports = app;

