const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs');

const db = require('./database/dbConfig.js');
const Users = require('./users/users-model.js');

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

server.get('/', (req, res) => {
  res.send("It's alive!");
});

server.post('/api/register', (req, res) => {
  let user = req.body;
  // generate hash from user's password
  const hash = bcrypt.hashSync(user.password, 16);
  // override user.password with hash
  user.password = hash

  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post('/api/login', (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      // check that passwords match
      if (user && bcrypt.compareSync(password, user.password)) {
        res.status(200).json({ message: `Welcome ${user.username}!` });
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

// protect this route, only authenticated users should see it
function restricted (req, res, next) {
  const { username, password } = req.headers

  if (username && password) {
    Users.findBy({ username })
      .first()
      .then(user => {
        if (user && bcrypt.compareSync(password, user.password)) {
          next();
        } else {
          res.status(401).json({ message: 'Invalid Credentials'});
        }
      })
      .catch(error => {
        res.status(500).json(error);
      })
  } else {
    res.status(400).json({ message: 'No Credentials Provided' });
  }
}

server.post('/api/users', restricted, (req, res) => {
  Users.find()
    .then(users => {
        res.json(users);
    })
    .catch(err => res.send(err));
});

server.get('/api/users', restricted, async (req, res) => {
  try {
    const users = await users.find()
    res.json(users)
  } catch(error) {
    res.send(error)
  }
})

const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
