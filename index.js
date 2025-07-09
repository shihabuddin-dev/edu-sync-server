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
    const notesCollection = db.collection("notes");

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
        const { email } = req.params;
        if (!email) {
          return res.status(400).send({ message: 'Email is required' });
        }
        const user = await usersCollection.findOne({ email });
        if (!user) {
          return res.status(404).send({ message: 'User not found' });
        }
        res.send({ role: user.role || 'student' });
      } catch (error) {
        console.error('Error getting user role:', error);
        res.status(500).send({ message: 'Failed to get role' });
      }
    });


    // users api
    app.get('/users', async (req, res) => {
      const result = await usersCollection.find().toArray()
      res.send(result)
    })

    // Add or update the POST /users endpoint to enforce default role 'student'
    app.post('/users', async (req, res) => {
      try {
        const userData = req.body;
        if (!userData.email) {
          return res.status(400).send({ message: 'Email is required' });
        }
        // Set default role to 'student' if not provided
        if (!userData.role) {
          userData.role = 'student';
        }
        // Upsert user (update if exists, insert if not)
        const result = await usersCollection.updateOne(
          { email: userData.email },
          { $setOnInsert: userData },
          { upsert: true }
        );
        res.send({ success: true, result });
      } catch (error) {
        console.error('Error creating user:', error);
        res.status(500).send({ message: 'Failed to create user' });
      }
    });

    // GET: Get notes api
    // verifyFBToken
    app.get('/notes', async (req, res) => {
      const { email } = req.query;
      if (!email) {
        return res.status(400).send({ message: 'Email query parameter is required' });
      }
      const result = await notesCollection.find({ email }).toArray();
      res.send(result);
    });

    // POST: Create a new note
    app.post('/notes', async (req, res) => {
      try {
        const { email, title, description, created_at } = req.body;
        if (!email || !title || !description) {
          return res.status(400).send({ message: 'Email, title, and description are required' });
        }
        const note = { email, title, description, created_at: created_at || new Date().toISOString() };
        const result = await notesCollection.insertOne(note);
        res.send({ success: true, noteId: result.insertedId });
      } catch (error) {
        console.error('Error creating note:', error);
        res.status(500).send({ message: 'Failed to create note' });
      }
    });

    // DELETE: Delete a note by ID
    app.delete('/notes/:id', async (req, res) => {
      try {
        const { id } = req.params;
        const result = await notesCollection.deleteOne({ _id: new ObjectId(id) });
        if (result.deletedCount === 0) {
          return res.status(404).send({ message: 'Note not found' });
        }
        res.send({ success: true });
      } catch (error) {
        console.error('Error deleting note:', error);
        res.status(500).send({ message: 'Failed to delete note' });
      }
    });

    // PATCH: Update a note by ID
    app.patch('/notes/:id', async (req, res) => {
      try {
        const { id } = req.params;
        const { title, description } = req.body;
        if (!title && !description) {
          return res.status(400).send({ message: 'Nothing to update' });
        }
        const updateDoc = {};
        if (title) updateDoc.title = title;
        if (description) updateDoc.description = description;
        const result = await notesCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updateDoc }
        );
        if (result.matchedCount === 0) {
          return res.status(404).send({ message: 'Note not found' });
        }
        res.send({ success: true });
      } catch (error) {
        console.error('Error updating note:', error);
        res.status(500).send({ message: 'Failed to update note' });
      }
    });

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
