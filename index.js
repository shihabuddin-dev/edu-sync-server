const express = require("express");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const cors = require("cors");
require("dotenv").config();
const app = express();
const port = process.env.PORT || 3000;
const admin = require("firebase-admin");

// const stripe = require("stripe")(process.env.PAYMENT_GATEWAY_KEY);

// Middleware
app.use(cors());
app.use(express.json());

// firebase admin
const decodedKey = Buffer.from(process.env.FB_SERVICE_KEY, 'base64').toString('utf8')
const serviceAccount = JSON.parse(decodedKey)

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});


// mongoDB
const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});


async function run() {
  try {
    // Database collections
    const db = client.db("eduSyncDB");
    const usersCollection = db.collection("users");

 // custom middlewares
 const verifyFBToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).send({ message: 'unauthorized access' })
  }
  const token = authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).send({ message: 'unauthorized access' })
  }


 // verify the token
      try {
        const decoded = await admin.auth().verifyIdToken(token);
        req.decoded = decoded;
        next();
      }
      catch (error) {
        return res.status(403).send({ message: 'forbidden access' })
      }
    }

    const verifyAdmin = async (req, res, next) => {
      const email = req.decoded.email;
      const query = { email }
      const user = await usersCollection.findOne(query);
      if (!user || user.role !== 'admin') {
        return res.status(403).send({ message: 'forbidden access' })
      }
      next();
    }

    const verifyTutor = async (req, res, next) => {
      const email = req.decoded.email;
      const query = { email }
      const user = await usersCollection.findOne(query);
      if (!user || user.role !== 'tutor') {
        return res.status(403).send({ message: 'forbidden access' })
      }
      next();
    }

     // GET: Get user role by email
     app.get('/users/:email/role', async (req, res) => {
      try {
        const email = req.params.email;
        if (!email) {
          return res.status(400).send({ message: 'Email is required' });
        }
        const user = await usersCollection.findOne({ email });
        if (!user) {
          return res.status(404).send({ message: 'User not found' });
        }
        res.send({ role: user.role || 'user' });
      } catch (error) {
        console.error('Error getting user role:', error);
        res.status(500).send({ message: 'Failed to get role' });
      }
    });

    app.get('/users', async(req, res)=>{
      const result= await usersCollection.find().toArray()
      res.send(result)
    })
    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("That's great! Server is running");
});

app.listen(port, (req, res) => {
  console.log(`Server is running on port http://localhost:${port}`);
});
