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
    const sessionsCollection = db.collection("sessions");
    const materialsCollection = db.collection("materials");
    const announcementsCollection = db.collection("announcements");

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

    // **User**
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

    // GET: Get user by _id (admin only)
    app.get('/users/:id', verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const { id } = req.params;
        if (!id) {
          return res.status(400).send({ message: 'User id is required' });
        }
        let user;
        try {
          user = await usersCollection.findOne({ _id: new ObjectId(id) });
        } catch (e) {
          return res.status(400).send({ message: 'Invalid user id' });
        }
        if (!user) {
          return res.status(404).send({ message: 'User not found' });
        }
        res.send(user);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch user by id' });
      }
    });


    // users api
    // verifyFBToken, verifyAdmin,
    app.get('/users', verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const { search } = req.query;
        let query = {};
        if (search) {
          query = {
            $or: [
              { name: { $regex: search, $options: 'i' } },
              { displayName: { $regex: search, $options: 'i' } },
              { email: { $regex: search, $options: 'i' } }
            ]
          };
        }

        const result = await usersCollection.find(query).toArray();
        res.send(result);
      } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).send({ message: 'Failed to fetch users' });
      }
    });

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
        // Prepare user document with all fields
        const userDocument = {
          email: userData.email,
          name: userData.name || userData.displayName || '',
          photoURL: userData.photoURL || '',
          role: userData.role,
          created_at: userData.created_at || new Date().toISOString(),
          last_log_in: userData.last_log_in || new Date().toISOString(),
        };
        // Upsert user (update if exists, insert if not)
        const result = await usersCollection.updateOne(
          { email: userData.email },
          { $setOnInsert: userDocument },
          { upsert: true }
        );
        res.send({ success: true, result });
      } catch (error) {
        console.error('Error creating user:', error);
        res.status(500).send({ message: 'Failed to create user' });
      }
    });

    // PATCH: Update user role
    app.patch('/users/:email/role', verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const { email } = req.params;
        const { role } = req.body;

        if (!email || !role) {
          return res.status(400).send({ message: 'Email and role are required' });
        }

        if (!['admin', 'tutor', 'student'].includes(role)) {
          return res.status(400).send({ message: 'Invalid role. Must be admin, tutor, or student' });
        }

        const result = await usersCollection.updateOne(
          { email },
          { $set: { role } }
        );

        if (result.matchedCount === 0) {
          return res.status(404).send({ message: 'User not found' });
        }

        res.send({ success: true, message: 'User role updated successfully' });
      } catch (error) {
        console.error('Error updating user role:', error);
        res.status(500).send({ message: 'Failed to update user role' });
      }
    });

    // **Notes**

    // GET: Get notes api
    // verifyFBToken
    app.get('/notes', verifyFBToken, async (req, res) => {
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


    // **Sessions**

    // GET: Public route for available study sessions (limit , only approved)
    app.get('/available-sessions', async (req, res) => {
      try {
        const sessions = await sessionsCollection
          .find({ status: 'approved' })
          .sort({ registrationEnd: 1 }) // soonest closing first
          .limit(8)
          .project({ title: 1, description: 1, registrationStart: 1, registrationEnd: 1, sessionImage: 1, tutorName: 1, duration: 1 })
          .toArray();

        res.send(sessions);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch available sessions' });
      }
    });

    // Public: Get all study sessions (no auth, show all statuses, hide tutorEmail)
    app.get('/public-sessions', async (req, res) => {
      try {
        const sessions = await sessionsCollection
          .find({})
          .project({ tutorEmail: 0 })
          .sort({ registrationEnd: 1 })
          .toArray();
        res.send(sessions);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch sessions' });
      }
    });

    // GET: Get all sessions for a tutor by email, or all sessions for admin
    app.get('/sessions', verifyFBToken, async (req, res) => {
      try {
        const { email } = req.query;
        const userEmail = req.decoded.email;
        let query = {};

        // Check if user is admin
        const user = await usersCollection.findOne({ email: userEmail });
        if (user && user.role === 'admin') {
          // Admin can see all sessions or filter by specific tutor email
          if (email) {
            query.tutorEmail = email;
          }
          // else, query is {} (all sessions for admin)
        } else if (user && user.role === 'tutor') {
          // Tutor can only see their own sessions
          query.tutorEmail = userEmail;
        } else {
          // Students or other roles cannot access sessions
          return res.status(403).send({ message: 'forbidden access' });
        }

        const result = await sessionsCollection.find(query).toArray();
        res.send(result);
      } catch (error) {
        console.error('Error fetching sessions:', error);
        res.status(500).send({ message: 'Failed to fetch sessions' });
      }
    });

    // GET: Get a single session by ID
    app.get('/sessions/:id', async (req, res) => {
      try {
        const { id } = req.params;
        const session = await sessionsCollection.findOne({ _id: new ObjectId(id) });
        if (!session) {
          return res.status(404).send({ message: 'Session not found' });
        }
        res.send(session);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch session' });
      }
    });

    // POST: Create a new study session
    app.post('/sessions', async (req, res) => {
      try {
        const session = req.body;
        // Basic validation
        if (!session.title || !session.tutorName || !session.tutorEmail || !session.description || !session.registrationStart || !session.registrationEnd || !session.classStart || !session.classEnd || !session.duration) {
          return res.status(400).send({ message: 'Missing required fields' });
        }
        // Set defaults if not provided
        if (!session.registrationFee) session.registrationFee = 0;
        if (!session.status) session.status = 'pending';
        session.created_at = session.created_at || new Date().toISOString();
        const result = await sessionsCollection.insertOne(session);
        res.send({ success: true, sessionId: result.insertedId });
      } catch (error) {
        console.error('Error creating session:', error);
        res.status(500).send({ message: 'Failed to create session' });
      }
    });

    // PATCH: Update session status by ID (approve/reject, set paid/registrationFee) - ADMIN ONLY
    app.patch('/sessions/:id/status', verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const { id } = req.params;
        const { status, paid, registrationFee } = req.body;
        if (!status) return res.status(400).send({ message: 'Status is required' });

        const updateDoc = { status };
        if (status === 'approved') {
          updateDoc.paid = !!paid;
          updateDoc.registrationFee = paid ? Number(registrationFee) : 0;
        }
        if (status === 'rejected') {
          // Optionally, add a rejectedAt timestamp or other logic
        }

        const result = await sessionsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updateDoc }
        );
        if (result.matchedCount === 0) {
          return res.status(404).send({ message: 'Session not found' });
        }
        res.send({ success: true });
      } catch (error) {
        res.status(500).send({ message: 'Failed to update session status' });
      }
    });

    // PATCH: Resubmit rejected session (TUTOR ONLY)
    app.patch('/sessions/:id/resubmit', verifyFBToken, verifyTutor, async (req, res) => {
      try {
        const { id } = req.params;
        const userEmail = req.decoded.email;

        // First, check if the session exists and belongs to this tutor
        const session = await sessionsCollection.findOne({ _id: new ObjectId(id) });
        if (!session) {
          return res.status(404).send({ message: 'Session not found' });
        }

        // Verify the session belongs to the requesting tutor
        if (session.tutorEmail !== userEmail) {
          return res.status(403).send({ message: 'You can only resubmit your own sessions' });
        }

        // Only allow resubmission if the session is currently rejected
        if (session.status !== 'rejected') {
          return res.status(400).send({ message: 'Only rejected sessions can be resubmitted' });
        }

        // Update the session status to pending
        const result = await sessionsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status: 'pending' } }
        );

        if (result.matchedCount === 0) {
          return res.status(404).send({ message: 'Session not found' });
        }

        res.send({ success: true, message: 'Session resubmitted successfully' });
      } catch (error) {
        console.error('Error resubmitting session:', error);
        res.status(500).send({ message: 'Failed to resubmit session' });
      }
    });

    // PUT: Update a session by ID (for admin update)
    app.put('/sessions/:id', verifyFBToken, async (req, res) => {
      try {
        const { id } = req.params;
        const updateData = req.body;
        const result = await sessionsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updateData }
        );
        if (result.matchedCount === 0) {
          return res.status(404).send({ message: 'Session not found' });
        }
        res.send({ success: true });
      } catch (error) {
        res.status(500).send({ message: 'Failed to update session' });
      }
    });

    // DELETE: Delete a session by ID
    app.delete('/sessions/:id', verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const { id } = req.params;
        const result = await sessionsCollection.deleteOne({ _id: new ObjectId(id) });
        if (result.deletedCount === 0) {
          return res.status(404).send({ message: 'Session not found' });
        }
        res.send({ success: true });
      } catch (error) {
        res.status(500).send({ message: 'Failed to delete session' });
      }
    });

    // **materials**

    // READ: Get all materials, or filter by sessionId or tutorEmail
    app.get('/materials', async (req, res) => {
      try {
        const { sessionId, tutorEmail } = req.query;
        const query = {};
        if (sessionId) query.sessionId = sessionId;
        if (tutorEmail) query.tutorEmail = tutorEmail;
        const materials = await materialsCollection.find(query).toArray();
        res.send(materials);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch materials' });
      }
    });

    // READ: Get a single material by ID
    app.get('/materials/:id', async (req, res) => {
      try {
        const { id } = req.params;
        const material = await materialsCollection.findOne({ _id: new ObjectId(id) });
        if (!material) {
          return res.status(404).send({ message: 'Material not found' });
        }
        res.send(material);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch material' });
      }
    });

    // CREATE: Upload a new material for a session
    app.post('/materials', async (req, res) => {
      try {
        const { title, sessionId, tutorEmail, imageUrl, resourceLink } = req.body;
        if (!title || !sessionId || !tutorEmail || !imageUrl || !resourceLink) {
          return res.status(400).send({ message: 'All fields are required' });
        }
        const material = {
          title,
          sessionId, // string, references the study session
          tutorEmail, // string, the tutor's email
          imageUrl,   // string, link to image (e.g. from ImgBB)
          resourceLink, // string, Google Drive link
          created_at: new Date().toISOString(),
        };
        const result = await materialsCollection.insertOne(material);
        res.send({ success: true, materialId: result.insertedId });
      } catch (error) {
        res.status(500).send({ message: 'Failed to upload material' });
      }
    });

    // UPDATE: Update a material by ID
    app.put('/materials/:id', async (req, res) => {
      try {
        const { id } = req.params;
        const updateData = req.body;
        const result = await materialsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updateData }
        );
        if (result.matchedCount === 0) {
          return res.status(404).send({ message: 'Material not found' });
        }
        res.send({ success: true });
      } catch (error) {
        res.status(500).send({ message: 'Failed to update material' });
      }
    });

    // DELETE: Delete a material by ID
    app.delete('/materials/:id', async (req, res) => {
      try {
        const { id } = req.params;
        const result = await materialsCollection.deleteOne({ _id: new ObjectId(id) });
        if (result.deletedCount === 0) {
          return res.status(404).send({ message: 'Material not found' });
        }
        res.send({ success: true });
      } catch (error) {
        res.status(500).send({ message: 'Failed to delete material' });
      }
    });

    // **Announcements**

    // GET: Get all announcements
    app.get('/announcements', async (req, res) => {
      try {
        const announcements = await announcementsCollection.find({}).toArray();
        res.send(announcements);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch announcements' });
      }
    });

    // POST: Create a new announcement (admin only)
    app.post('/announcements', verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const { title, message, category, audience, priority, link, imageUrl } = req.body;
        if (!title || !message) {
          return res.status(400).send({ message: 'Title and message are required' });
        }
        const announcement = {
          title,
          message,
          category: category || '',
          audience: audience || '',
          priority: priority || '',
          link: link || '',
          imageUrl: imageUrl || '',
          created_at: new Date().toISOString(),
        };
        const result = await announcementsCollection.insertOne(announcement);
        res.send({ success: true, announcementId: result.insertedId });
      } catch (error) {
        res.status(500).send({ message: 'Failed to create announcement' });
      }
    });



    // **End Of The API**

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
