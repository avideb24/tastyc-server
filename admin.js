// verify token middleware
const verifyToken = (req, res, next) => {
    // console.log(req.headers.authorization);
    if(!req.headers.authorization){
      return res.status(401).send({message: 'forbidden access'})
    };

    const token = req.headers.authorization.split(' ')[1];

    // console.log('token from db',token);

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
      if(err){
        return res.status(401).send({message: 'forbidden access'})
      };
      res.decoded = decoded;
      next();
    })
  }

  const verifyAdmin = async (req, res, next) => {
    const email = req.decoded.email;
    const query = { email: email };
    const user = await userCollection.findOne(query);
    const isAdmin = user?.role === 'admin';
    if (!isAdmin) {
      return res.status(403).send({ message: 'forbidden access' });
    }
    next();
  }


     // jwt api
     app.post('/jwt', async(req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '1hr'});
      res.send({token});
    })

  // admin verify
  app.get('/users/admin/:email', verifyToken, async(req, res) => {
    const email = req.params.email;
    if(email !== req.decoded.email){
      return res.status(401).send({message: 'Unauthorized access'})
    };
    const query = {email : email};
    const user = await userCollection.findOne(query);
    let admin = false;
    if(user){
      admin = user?.role === 'admin'
    }
    res.send({admin})
  })

  // user patch (make admin)
  app.patch('/users/admin/:id', verifyToken, verifyAdmin, async(req, res) => {
    const id = req.params.id;
    const filter = { _id: new ObjectId(id) };
    const updatedDoc = {
      $set: {
        role: "admin"
      }
    };
    const result = await userCollection.updateOne(filter, updatedDoc);
    res.send(result);
  })