import React, { useEffect, useRef, useState } from "react";
import { supabase } from "./lib/supabase";
import ForceGraph2D from "react-force-graph-2d";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";

export default function App() {
  // =========================
  // AUTH / USER STATE
  // =========================

  const [session, setSession] = useState(null);
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // =========================
  // LOGIN STATE
  // =========================

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [fullName, setFullName] = useState("");
  const [isSignup, setIsSignup] = useState(false);
  const [authLoading, setAuthLoading] = useState(false);

  // =========================
  // INVESTIGATION STATE
  // =========================

  const [investigations, setInvestigations] = useState([]);
  const [selected, setSelected] = useState(null);

  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newTitle, setNewTitle] = useState("");
  const [newDescription, setNewDescription] = useState("");
  const [creating, setCreating] = useState(false);

  // =========================
  // FIR / NLP STATE
  // =========================

  const [firText, setFirText] = useState("");
  const [firEntities, setFirEntities] = useState([]);
  const [firAnalyzing, setFirAnalyzing] = useState(false);

  // =========================
  // TIP / NETWORK STATE
  // =========================

  const [tipText, setTipText] = useState("");
  const [tipResult, setTipResult] = useState(null);
  const [tipAnalyzing, setTipAnalyzing] = useState(false);

  const [graph, setGraph] = useState({
    nodes: [],
    links: [],
  });

  const [graphLoading, setGraphLoading] = useState(false);
  const graphRef = useRef(null);
  const [selectedRelationship, setSelectedRelationship] = useState(null);
const [peopleMap, setPeopleMap] = useState({});

  // =========================
  // CRIMINAL NETWORK SEARCH
  // =========================

  const [criminalSearch, setCriminalSearch] = useState("");
  const [criminalResults, setCriminalResults] = useState([]);
  const [searchLoading, setSearchLoading] = useState(false);
  const [showSearchResults, setShowSearchResults] = useState(false);
  const [selectedCriminal, setSelectedCriminal] = useState(null);
  const [hoveredNode, setHoveredNode] = useState(null);

  // Keep the network spacious without pinning nodes.
  // Nodes start in a radial layout, then D3 is free to move them.
  useEffect(() => {
    const fg = graphRef.current;
    if (!fg || !graph.nodes.length) return;

    const charge = fg.d3Force("charge");
    if (charge) {
      charge.strength(-1400).distanceMax(1400);
    }

    const link = fg.d3Force("link");
    if (link) {
      link.distance(300).strength(0.45);
    }

    const center = fg.d3Force("center");
    if (center) {
      center.strength(0.035);
    }

    // Extra collision force implemented locally so we don't need another package.
    const collideForce = () => {
      const nodes = graph.nodes;
      const padding = 78;
      for (let i = 0; i < nodes.length; i += 1) {
        for (let j = i + 1; j < nodes.length; j += 1) {
          const a = nodes[i];
          const b = nodes[j];
          if (typeof a.x !== "number" || typeof b.x !== "number") continue;
          const dx = b.x - a.x;
          const dy = b.y - a.y;
          const distance = Math.sqrt(dx * dx + dy * dy) || 0.01;
          const minimum = (a.is_center ? 55 : 42) + (b.is_center ? 55 : 42) + padding;
          if (distance < minimum) {
            const push = (minimum - distance) / distance * 0.5;
            const px = dx * push;
            const py = dy * push;
            a.vx -= px;
            a.vy -= py;
            b.vx += px;
            b.vy += py;
          }
        }
      }
    };
    collideForce.initialize = () => {};
    fg.d3Force("collision", collideForce);

    fg.d3ReheatSimulation();

    const timer = setTimeout(() => {
      if (graphRef.current) {
        graphRef.current.zoomToFit(700, 95);
      }
    }, 900);

    return () => clearTimeout(timer);
  }, [graph]);

  // ============================================================
  // INITIAL SESSION
  // ============================================================

  useEffect(() => {
    let mounted = true;

    async function initialize() {
      try {
        setLoading(true);
        setError("");

        const {
          data: { session },
          error: sessionError,
        } = await supabase.auth.getSession();

        if (sessionError) {
          throw sessionError;
        }

        if (!mounted) return;

        setSession(session);

        if (session) {
          await loadProfile(session.user.id);
        }
      } catch (err) {
        console.error("Initialization error:", err);
        if (mounted) {
          setError(err.message || "Unable to initialize application.");
        }
      } finally {
        if (mounted) {
          setLoading(false);
        }
      }
    }

    initialize();

    // ============================================================
    // AUTH STATE LISTENER
    // ============================================================

    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((_event, newSession) => {
      setSession(newSession);

      // Important:
      // Clear old user information before loading the new user's profile.
      setProfile(null);
      setInvestigations([]);
      setSelected(null);
      setGraph({
        nodes: [],
        links: [],
      });
      setSelectedRelationship(null);
      setPeopleMap({});
      setCriminalSearch("");
      setCriminalResults([]);
      setShowSearchResults(false);
      setSelectedCriminal(null);
      setHoveredNode(null);

      if (!newSession) {
        return;
      }

      // Avoid Supabase auth callback deadlocks.
      setTimeout(() => {
        loadProfile(newSession.user.id);
      }, 0);
    });

    return () => {
      mounted = false;
      subscription.unsubscribe();
    };
  }, []);

  // ============================================================
  // LOAD PROFILE
  // ============================================================

  async function loadProfile(userId) {
    try {
      setError("");

      const { data, error } = await supabase
        .from("profiles")
        .select("*")
        .eq("id", userId)
        .maybeSingle();

      if (error) {
        throw error;
      }

      setProfile(data);

      if (data?.is_authorized === true) {
        await loadInvestigations();
      }
    } catch (err) {
      console.error("Profile error:", err);
      setError(err.message || "Unable to load profile.");
    }
  }

  // ============================================================
  // LOAD INVESTIGATIONS
  // ============================================================

  async function loadInvestigations() {
    try {
      const { data, error } = await supabase
        .from("investigations")
        .select("*")
        .order("created_at", {
          ascending: false,
        });

      if (error) {
        throw error;
      }

      setInvestigations(data || []);

      if (data && data.length > 0 && !selected) {
        setSelected(data[0]);
      }
    } catch (err) {
      console.error("Investigation loading error:", err);
      setError(err.message || "Unable to load investigations.");
    }
  }

  // ============================================================
  // LOGIN / SIGNUP
  // ============================================================

  async function handleAuth(event) {
    event.preventDefault();

    if (!email.trim() || !password.trim()) {
      setError("Email and password are required.");
      return;
    }

    setAuthLoading(true);
    setError("");

    try {
      if (isSignup) {
        // -------------------------
        // SIGN UP
        // -------------------------

        const {
          data,
          error,
        } = await supabase.auth.signUp({
          email: email.trim(),
          password,
          options: {
            data: {
              full_name: fullName.trim(),
            },
          },
        });

        if (error) {
          throw error;
        }

        if (data.user && !data.session) {
          alert(
            "Account created successfully. Please verify your email if email confirmation is enabled."
          );
        }
      } else {
        // -------------------------
        // LOGIN
        // -------------------------

        const {
          data,
          error,
        } = await supabase.auth.signInWithPassword({
          email: email.trim(),
          password,
        });

        if (error) {
          throw error;
        }

        if (data.session) {
          setSession(data.session);
          await loadProfile(data.session.user.id);
        }
      }
    } catch (err) {
      console.error("Authentication error:", err);
      setError(err.message || "Authentication failed.");
    } finally {
      setAuthLoading(false);
    }
  }

  // ============================================================
  // CREATE INVESTIGATION
  // ============================================================

  async function createInvestigation() {
    if (!newTitle.trim()) {
      setError("Investigation title is required.");
      return;
    }

    if (!session?.user?.id) {
      setError("You must be logged in.");
      return;
    }

    setCreating(true);
    setError("");

    try {
      const { data, error } = await supabase
        .from("investigations")
        .insert({
          title: newTitle.trim(),
          description: newDescription.trim(),
          created_by: session.user.id,
          status: "active",
        })
        .select("*")
        .single();

      if (error) {
        throw error;
      }

      // Add newly created investigation to UI.
      setInvestigations((previous) => [data, ...previous]);

      // Automatically select it.
      setSelected(data);

      // Reset modal.
      setNewTitle("");
      setNewDescription("");
      setShowCreateModal(false);

      alert(
        `Investigation created successfully.\n\nInvestigation ID: ${data.investigation_code}`
      );
    } catch (err) {
      console.error("Create investigation error:", err);
      setError(err.message || "Unable to create investigation.");
    } finally {
      setCreating(false);
    }
  }

  // ============================================================
  // FIR NLP ANALYSIS
  // ============================================================

  async function analyzeFIR() {
  if (!selected) {
    setError("Please select an investigation first.");
    return;
  }

  if (!firText.trim()) {
    setError("Please enter FIR/report text first.");
    return;
  }

  setFirAnalyzing(true);
  setFirEntities([]);
  setError("");

  try {
    const response = await fetch(`${API}/api/nlp/extract`, {
      method: "POST",
      headers: {
  "Content-Type": "application/json",
  Authorization: `Bearer ${session.access_token}`,
},
      body: JSON.stringify({
        investigation_id: selected.id,
        source_type: "FIR",
        title: "FIR Analysis",
        content: firText,
      }),
    });

    const rawText = await response.text();

    let data;

    try {
      data = JSON.parse(rawText);
    } catch {
      data = {
        detail: rawText,
      };
    }

    console.log("NLP status:", response.status);
    console.log("NLP response:", data);

    if (!response.ok) {
      let message =
        data.detail ||
        data.message ||
        "FIR analysis failed.";

      if (typeof message !== "string") {
        message = JSON.stringify(message, null, 2);
      }

      throw new Error(message);
    }

    const entities = [];

if (data.entities) {
  Object.entries(data.entities).forEach(([label, values]) => {
    if (Array.isArray(values)) {
      values.forEach((value) => {
        entities.push({
          label,
          text: value,
        });
      });
    }
  });
}

setFirEntities(entities);
  } catch (err) {
    console.error("FIR analysis error:", err);

    setError(
      err instanceof Error
        ? err.message
        : JSON.stringify(err, null, 2)
    );
  } finally {
    setFirAnalyzing(false);
  }
}
  // ============================================================
  // TIP ANALYSIS
  // ============================================================

  async function analyzeTip() {
    if (!selected) {
      setError("Please select an investigation first.");
      return;
    }

    if (!tipText.trim()) {
      setError("Please enter a tip.");
      return;
    }

    setTipAnalyzing(true);
    setTipResult(null);
    setError("");

    try {
      const response = await fetch(`${API}/api/tips/analyze`, {
        method: "POST",
       headers: {
  "Content-Type": "application/json",
  Authorization: `Bearer ${session.access_token}`,
},
        body: JSON.stringify({
          investigation_id: selected.id,
          text: tipText,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail || "Tip analysis failed."
        );
      }

      setTipResult(data);
    } catch (err) {
      console.error("Tip analysis error:", err);
      setError(
        err.message ||
          "Unable to analyze tip."
      );
    } finally {
      setTipAnalyzing(false);
    }
  }

  // ============================================================
  // CRIMINAL SEARCH
  // ============================================================

  async function searchCriminals(query) {
    if (!selected || !session?.access_token) return;

    const value = query.trim();

    if (!value) {
      setCriminalResults([]);
      setShowSearchResults(false);
      return;
    }

    setSearchLoading(true);

    try {
      const response = await fetch(
        `${API}/api/investigations/${selected.id}/persons/search?q=${encodeURIComponent(value)}`,
        {
          headers: {
            Authorization: `Bearer ${session.access_token}`,
          },
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "Unable to search persons.");
      }

      setCriminalResults(data || []);
      setShowSearchResults(true);
    } catch (err) {
      console.error("Criminal search error:", err);
      setError(err.message || "Unable to search persons.");
    } finally {
      setSearchLoading(false);
    }
  }

  async function loadCriminalNetwork(person) {
    if (!selected || !session?.access_token || !person) return;

    setSelectedCriminal(person);
    setCriminalSearch(person.name || "");
    setCriminalResults([]);
    setShowSearchResults(false);
    setSelectedRelationship(null);
    setGraphLoading(true);
    setError("");

    try {
      const response = await fetch(
        `${API}/api/investigations/${selected.id}/network/${encodeURIComponent(person.person_id)}`,
        {
          headers: {
            Authorization: `Bearer ${session.access_token}`,
          },
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "Unable to load criminal network.");
      }

      const map = {};
      (data.nodes || []).forEach((node) => {
        map[node.id] = node.name;
      });

      setPeopleMap(map);
      // Seed the graph with a centered subject and evenly spaced
      // surrounding nodes. The force simulation will refine these
      // positions while keeping the network readable.
      const rawNodes = data.nodes || [];
      const centerNode = rawNodes.find(
        (node) => node.id === person.person_id
      );
      const connectedNodes = rawNodes.filter(
        (node) => node.id !== person.person_id
      );

      const seededNodes = rawNodes.map((node) => {
        if (node.id === person.person_id) {
          return { ...node, x: 0, y: 0 };
        }

        const index = connectedNodes.findIndex(
          (item) => item.id === node.id
        );
        const count = Math.max(connectedNodes.length, 1);
        const angle = (index / count) * Math.PI * 2 - Math.PI / 2;
        const radius = connectedNodes.length <= 8 ? 300 : 340;

        return {
          ...node,
          x: Math.cos(angle) * radius,
          y: Math.sin(angle) * radius,
        };
      });

      setGraph({
        nodes: seededNodes,
        links: data.links || [],
      });

      // Use the complete person record returned by the network endpoint
      // when it is available.
      const center = (data.nodes || []).find(
        (node) => node.id === person.person_id
      );

      if (center) {
        setSelectedCriminal({
          ...person,
          ...center,
        });
      }
    } catch (err) {
      console.error("Criminal network loading error:", err);
      setError(err.message || "Unable to load criminal network.");
    } finally {
      setGraphLoading(false);
    }
  }

  function clearCriminalSearch() {
    setCriminalSearch("");
    setCriminalResults([]);
    setShowSearchResults(false);
    setSelectedCriminal(null);
    setSelectedRelationship(null);
    setHoveredNode(null);
    setGraph({ nodes: [], links: [] });
  }

  // ============================================================
  // LOAD NETWORK GRAPH
  // ============================================================

  async function loadGraph() {
  if (!selected) {
    setError("Please select an investigation first.");
    return;
  }

  setGraphLoading(true);
  setError("");

  try {
    const response = await fetch(
      `${API}/api/investigations/${selected.id}/graph`,
      {
        headers: {
          Authorization: `Bearer ${session.access_token}`,
        },
      }
    );

    const data = await response.json();

    if (!response.ok) {
      throw new Error(
        data.detail || "Unable to load network graph."
      );
    }

    // Create ID → name lookup
    const map = {};

    (data.nodes || []).forEach((person) => {
      map[person.id] = person.name;
    });

    setPeopleMap(map);

    // Give every connected person a clearly separated starting position.
    // These are NOT fixed positions; D3 can move them after the simulation starts.
    const rawNodes = data.nodes || [];
    const centerNode = rawNodes.find((node) => node.is_center) || rawNodes[0];
    const connectedNodes = rawNodes.filter((node) => node.id !== centerNode?.id);
    const radius = Math.max(260, Math.min(430, 220 + connectedNodes.length * 24));

    const arrangedNodes = rawNodes.map((node) => {
      if (node.id === centerNode?.id) {
        return { ...node, x: 0, y: 0 };
      }

      const index = connectedNodes.findIndex((item) => item.id === node.id);
      const angle = (index / Math.max(connectedNodes.length, 1)) * Math.PI * 2 - Math.PI / 2;

      return {
        ...node,
        x: Math.cos(angle) * radius,
        y: Math.sin(angle) * radius,
      };
    });

    setGraph({
      nodes: arrangedNodes,
      links: data.links || [],
    });

    // Clear previously selected relationship
    setSelectedRelationship(null);

  } catch (err) {
    console.error("Graph loading error:", err);

    setError(
      err.message ||
        "Unable to load network graph."
    );
  } finally {
    setGraphLoading(false);
  }
}

  // ============================================================
  // LOGOUT
  // ============================================================

  async function signOut() {
    await supabase.auth.signOut();

    setSession(null);
    setProfile(null);
    setInvestigations([]);
    setSelected(null);
    setFirText("");
    setFirEntities([]);
    setTipText("");
    setTipResult(null);
    setGraph({
      nodes: [],
      links: [],
    });
    setCriminalSearch("");
    setCriminalResults([]);
    setShowSearchResults(false);
    setSelectedCriminal(null);
    setSelectedRelationship(null);
    setPeopleMap({});
    setHoveredNode(null);
  }

  // ============================================================
  // LOADING SCREEN
  // ============================================================

  if (loading) {
    return (
      <div className="app-shell">
        <div className="loading-screen">
          <div className="loading-card">
            <div className="loading-logo">
              NYAYANET
            </div>

            <div className="loading-title">
              LOADING SECURE WORKSPACE
            </div>

            <div className="loading-subtitle">
              Authenticating investigative environment...
            </div>
          </div>
        </div>
      </div>
    );
  }

  // ============================================================
  // LOGIN SCREEN
  // ============================================================

  if (!session) {
    return (
      <div className="app-shell">
        <div className="auth-screen">
          <div className="auth-card">

            <div className="brand">
              <div className="brand-mark">
                N
              </div>

              <div>
                <h1>NyayaNet</h1>
                <p>
                  AI-Powered Criminal Network Analysis
                </p>
              </div>
            </div>

            <div className="auth-header">
              <h2>
                {isSignup
                  ? "Create Account"
                  : "Secure Login"}
              </h2>

              <p>
                Authorized investigative intelligence platform
              </p>
            </div>

            {error && (
              <div className="error-box">
                {error}
              </div>
            )}

            <form onSubmit={handleAuth}>

              {isSignup && (
                <div className="form-group">
                  <label>Full Name</label>

                  <input
                    type="text"
                    placeholder="Enter your full name"
                    value={fullName}
                    onChange={(e) =>
                      setFullName(e.target.value)
                    }
                  />
                </div>
              )}

              <div className="form-group">
                <label>Email</label>

                <input
                  type="email"
                  placeholder="investigator@example.com"
                  value={email}
                  onChange={(e) =>
                    setEmail(e.target.value)
                  }
                />
              </div>

              <div className="form-group">
                <label>Password</label>

                <input
                  type="password"
                  placeholder="Enter password"
                  value={password}
                  onChange={(e) =>
                    setPassword(e.target.value)
                  }
                />
              </div>

              <button
                type="submit"
                className="primary-button"
                disabled={authLoading}
              >
                {authLoading
                  ? "Authenticating..."
                  : isSignup
                  ? "Create Account"
                  : "Login Securely"}
              </button>
            </form>

            <button
              className="switch-auth"
              onClick={() => {
                setIsSignup(!isSignup);
                setError("");
              }}
            >
              {isSignup
                ? "Already have an account? Login"
                : "Need an account? Create one"}
            </button>

            <div className="security-note">
              🔒 Access is controlled through Supabase
              authentication and authorization.
            </div>

          </div>
        </div>
      </div>
    );
  }

  // ============================================================
  // UNAUTHORIZED USER
  // ============================================================

  if (!profile || profile.is_authorized !== true) {
    return (
      <div className="app-shell">
        <div className="restricted-screen">

          <div className="restricted-card">

            <div className="restricted-icon">
              🔒
            </div>

            <h1>Access Restricted</h1>

            <p>
              Your account is authenticated, but you are
              not currently authorized to access the
              investigative workspace.
            </p>

            <div className="restricted-user">
              <strong>
                {profile?.full_name ||
                  session.user.email}
              </strong>

              <span>
                {profile?.role ||
                  "Unauthorized User"}
              </span>
            </div>

            <button
              className="ghost"
              onClick={signOut}
            >
              Sign Out
            </button>

          </div>

        </div>
      </div>
    );
  }

  // ============================================================
  // MAIN AUTHORIZED DASHBOARD
  // ============================================================

  return (
    <div className="app-shell">

      {/* ========================================================
          SIDEBAR
      ======================================================== */}

      <aside className="sidebar">

        <div className="sidebar-brand">

          <div className="brand-mark">
            N
          </div>

          <div>
            <h1>NyayaNet</h1>

            <span>
              INVESTIGATIVE INTELLIGENCE
            </span>
          </div>

        </div>

        <div className="sidebar-section">

          <div className="sidebar-section-header">
            <span>INVESTIGATIONS</span>

            <button
              className="new-investigation-button"
              onClick={() =>
                setShowCreateModal(true)
              }
            >
              + New
            </button>
          </div>

          <div className="investigation-list">

            {investigations.length === 0 ? (
              <div className="sidebar-empty">
                No investigations yet.
              </div>
            ) : (
              investigations.map((investigation) => (
                <button
                  key={investigation.id}
                  className={`investigation-item ${
                    selected?.id === investigation.id
                      ? "active"
                      : ""
                  }`}
                  onClick={() => {
                    setSelected(investigation);

                    setTipResult(null);
                    setFirEntities([]);

                    setGraph({
                      nodes: [],
                      links: [],
                    });
                    setCriminalSearch("");
                    setCriminalResults([]);
                    setShowSearchResults(false);
                    setSelectedCriminal(null);
                    setSelectedRelationship(null);
                    setPeopleMap({});
                    setHoveredNode(null);
                  }}
                >
                  <span className="investigation-code">
                    {investigation.investigation_code}
                  </span>

                  <strong>
                    {investigation.title}
                  </strong>

                  <small>
                    {investigation.status}
                  </small>
                </button>
              ))
            )}

          </div>
        </div>

        <div className="sidebar-bottom">

          <div className="user-card">

            <div className="user-avatar">
              {(profile.full_name ||
                session.user.email ||
                "U")
                .charAt(0)
                .toUpperCase()}
            </div>

            <div className="user-info">
              <strong>
                {profile.full_name ||
                  session.user.email}
              </strong>

              <span>
                {profile.role ||
                  "Investigator"}
              </span>
            </div>

          </div>

          <button
            className="logout-button"
            onClick={signOut}
          >
            Sign Out
          </button>

        </div>

      </aside>

      {/* ========================================================
          MAIN CONTENT
      ======================================================== */}

      <main className="main">

        {/* HEADER */}

        <header className="topbar">

          <div>
            <div className="eyebrow">
              SECURE INVESTIGATIVE WORKSPACE
            </div>

            <h2>
              Criminal Network Analysis
            </h2>
          </div>

          <div className="topbar-status">
            <span className="status-dot"></span>
            AUTHORIZED
          </div>

        </header>

        {/* ERROR */}

        {error && (
          <div className="error-box main-error">
            {error}

            <button
              onClick={() => setError("")}
            >
              ×
            </button>
          </div>
        )}

        {/* ======================================================
            SELECTED INVESTIGATION
        ====================================================== */}

        {selected ? (
          <section className="investigation-banner">

            <div>
              <span>
                ACTIVE INVESTIGATION
              </span>

              <h3>
                {selected.title}
              </h3>

              <p>
                {selected.description ||
                  "No investigation description provided."}
              </p>
            </div>

            <div className="investigation-id">

              <span>
                INVESTIGATION ID
              </span>

              <strong>
                {selected.investigation_code}
              </strong>

            </div>

          </section>
        ) : (
          <section className="empty-dashboard">

            <div className="empty-icon">
              +
            </div>

            <h2>
              Select an Investigation
            </h2>

            <p>
              Select an existing investigation from
              the sidebar or create a new one.
            </p>

            <button
              onClick={() =>
                setShowCreateModal(true)
              }
            >
              Create Investigation
            </button>

          </section>
        )}

        {/* ======================================================
            FIR INTELLIGENCE
        ====================================================== */}

        <section className="panel">

          <div className="panel-header">

            <div>
              <div className="eyebrow">
                NLP ENGINE
              </div>

              <h2>
                FIR Intelligence
              </h2>

              <p className="muted">
                Extract people, locations, organizations,
                phones, vehicles and other entities from
                investigation documents.
              </p>
            </div>

            <div className="panel-badge">
              AI
            </div>

          </div>

          {!selected ? (
            <div className="empty-state">
              Select an investigation first.
            </div>
          ) : (
            <>
              <div className="selected-investigation">

                <span>
                  ACTIVE INVESTIGATION
                </span>

                <strong>
                  {selected.investigation_code}
                </strong>

                <small>
                  {selected.title}
                </small>

              </div>

              <textarea
                className="fir-input"
                placeholder="Paste FIR / police report / intelligence report here..."
                rows={12}
                value={firText}
                onChange={(e) =>
                  setFirText(e.target.value)
                }
              />

              <div className="fir-actions">

                <button
                  onClick={analyzeFIR}
                  disabled={
                    firAnalyzing ||
                    !firText.trim()
                  }
                >
                  {firAnalyzing
                    ? "Analyzing..."
                    : "Analyze FIR"}
                </button>

                <button
                  className="ghost"
                  onClick={() => {
                    setFirText("");
                    setFirEntities([]);
                  }}
                >
                  Clear
                </button>

              </div>

              {/* ENTITY RESULTS */}

              {firEntities.length > 0 && (
                <div className="entity-results">

                  <div className="panel-header">

                    <div>
                      <h3>
                        Extracted Entities
                      </h3>

                      <p className="muted">
                        Entities identified by the
                        NLP processing pipeline.
                      </p>
                    </div>

                    <div className="entity-count">
                      {firEntities.length} found
                    </div>

                  </div>

                  <div className="entity-grid">

                    {firEntities.map(
                      (entity, index) => (
                        <div
                          className="entity-card"
                          key={`${entity.text}-${index}`}
                        >

                          <span className="entity-type">
                            {entity.label ||
                              entity.type ||
                              "ENTITY"}
                          </span>

                          <strong>
                            {entity.text}
                          </strong>

                        </div>
                      )
                    )}

                  </div>

                </div>
              )}

            </>
          )}

        </section>

        {/* ======================================================
            TIP ANALYSIS
        ====================================================== */}

        <section className="panel">

          <div className="panel-header">

            <div>
              <div className="eyebrow">
                INTELLIGENCE INPUT
              </div>

              <h2>
                Tip → Network Analysis
              </h2>

              <p className="muted">
                Provide a small piece of intelligence
                and let the system identify possible
                entities and relationships.
              </p>
            </div>

          </div>

          {!selected ? (
            <div className="empty-state">
              Select an investigation first.
            </div>
          ) : (
            <>
              <textarea
                className="fir-input"
                placeholder="Enter an intelligence tip..."
                rows={7}
                value={tipText}
                onChange={(e) =>
                  setTipText(e.target.value)
                }
              />

              <div className="fir-actions">

                <button
                  onClick={analyzeTip}
                  disabled={
                    tipAnalyzing ||
                    !tipText.trim()
                  }
                >
                  {tipAnalyzing
                    ? "Analyzing..."
                    : "Analyze Tip"}
                </button>

                <button
                  className="ghost"
                  onClick={() => {
                    setTipText("");
                    setTipResult(null);
                  }}
                >
                  Clear
                </button>

              </div>

              {tipResult && (
                <div className="tip-result">

                  <h3>
                    Analysis Result
                  </h3>

                  <pre>
                    {JSON.stringify(
                      tipResult,
                      null,
                      2
                    )}
                  </pre>

                </div>
              )}

            </>
          )}

        </section>

        {/* ======================================================
            NETWORK GRAPH
        ====================================================== */}

        <section className="panel graph-panel network-explorer-panel">

          <div className="network-explorer-header">
            <div>
              <div className="eyebrow">NETWORK INTELLIGENCE</div>
              <h2>Criminal Network Explorer</h2>
              <p className="muted">
                Search for a person and explore their connected network.
              </p>
            </div>

            <div className="network-legend">
              <span className="legend-item">
                <i className="legend-dot selected"></i>
                Selected Subject
              </span>
              <span className="legend-item">
                <i className="legend-dot connected"></i>
                Connected Person
              </span>
              <span className="legend-item">
                <i className="legend-info">i</i>
                Hover for details
              </span>
            </div>
          </div>

          {!selected ? (
            <div className="empty-state">Select an investigation first.</div>
          ) : (
            <>
              {/* SEARCH + RESULTS */}
              <div className="network-search-layout">
                <div className="network-search-card">
                  <div className="search-card-title">
                    <div>
                      <span className="search-card-eyebrow">SUBJECT SEARCH</span>
                      <h3>Search Criminal</h3>
                    </div>
                    <span className="search-icon-badge">⌕</span>
                  </div>

                  <div className="network-search-wrapper">
                    <span className="network-search-icon">⌕</span>
                    <input
                      type="text"
                      className="network-search-input"
                      placeholder="Search by name, phone, vehicle or organization..."
                      value={criminalSearch}
                      onChange={(e) => {
                        const value = e.target.value;
                        setCriminalSearch(value);
                        searchCriminals(value);
                      }}
                      onFocus={() => {
                        if (criminalResults.length) setShowSearchResults(true);
                      }}
                    />
                    {criminalSearch && (
                      <button
                        type="button"
                        className="network-search-clear"
                        onClick={clearCriminalSearch}
                        aria-label="Clear search"
                      >
                        ×
                      </button>
                    )}
                    {searchLoading && <span className="network-search-spinner">Searching…</span>}
                  </div>

                  <p className="search-helper">
                    Search by name, phone number, vehicle number, or organization.
                  </p>

                  {showSearchResults && criminalSearch.trim() && (
                    <div className="network-search-results">
                      <div className="results-header">
                        <span>SEARCH RESULTS</span>
                        <b>{criminalResults.length}</b>
                      </div>

                      {criminalResults.length > 0 ? (
                        criminalResults.map((person) => (
                          <button
                            type="button"
                            key={person.id}
                            className="network-result-item"
                            onClick={() => loadCriminalNetwork(person)}
                          >
                            <div className="result-avatar">
                              {(person.name || "?")
                                .split(" ")
                                .map((part) => part[0])
                                .join("")
                                .slice(0, 2)
                                .toUpperCase()}
                            </div>
                            <div className="result-person">
                              <strong>{person.name}</strong>
                              <span>
                                {person.person_id}
                                {person.location ? ` · ${person.location}` : ""}
                              </span>
                              {person.phone_num && <small>☎ {person.phone_num}</small>}
                            </div>
                            <span className="result-arrow">›</span>
                          </button>
                        ))
                      ) : !searchLoading ? (
                        <div className="network-no-results">
                          No matching person found.
                        </div>
                      ) : null}
                    </div>
                  )}
                </div>

                {/* SELECTED SUBJECT SUMMARY */}
                {selectedCriminal && (
                  <div className="subject-summary-card">
                    <div className="subject-avatar-large">
                      {(selectedCriminal.name || "?")
                        .split(" ")
                        .map((part) => part[0])
                        .join("")
                        .slice(0, 2)
                        .toUpperCase()}
                    </div>
                    <div className="subject-main">
                      <span>SELECTED SUBJECT</span>
                      <strong>{selectedCriminal.name}</strong>
                      <small>
                        {selectedCriminal.person_id}
                        {selectedCriminal.location ? ` · ${selectedCriminal.location}` : ""}
                      </small>
                    </div>
                    <div className="subject-stat">
                      <span>AGE</span>
                      <strong>{selectedCriminal.age ?? "N/A"}</strong>
                    </div>
                    <div className="subject-stat">
                      <span>CONNECTIONS</span>
                      <strong>{Math.max(0, graph.nodes.length - 1)}</strong>
                    </div>
                    <div className="subject-stat subject-wide">
                      <span>PHONE</span>
                      <strong>{selectedCriminal.phone_num || "N/A"}</strong>
                    </div>
                    <div className="subject-stat subject-wide">
                      <span>VEHICLE</span>
                      <strong>{selectedCriminal.vehicle_num || "N/A"}</strong>
                    </div>
                  </div>
                )}
              </div>

              {/* GRAPH + DETAILS */}
              {!selectedCriminal ? (
                <div className="network-empty-state">
                  <div className="network-empty-icon">⌕</div>
                  <h3>Search for a Criminal</h3>
                  <p>
                    Select a person from the search results to build their relationship network.
                  </p>
                </div>
              ) : graphLoading ? (
                <div className="network-empty-state">
                  <div className="network-loading-ring"></div>
                  <h3>Building Network</h3>
                  <p>Finding all recorded connections for {selectedCriminal.name}…</p>
                </div>
              ) : (
                <div className="network-workspace">
                  <div className="network-graph-card">
                    <div className="network-graph-toolbar">
                      <div>
                        <span>RELATIONSHIP MAP</span>
                        <strong>
                          {graph.links.length} connection{graph.links.length === 1 ? "" : "s"} found
                        </strong>
                      </div>
                      <button
                        type="button"
                        className="network-reset-button"
                        onClick={() => {
                          setSelectedRelationship(null);
                          setHoveredNode(null);
                        }}
                      >
                        ↻ Reset View
                      </button>
                    </div>

                    <div className="network-canvas-wrap">
                      <ForceGraph2D
                        ref={graphRef}
                        graphData={graph}
                        width={undefined}
                        height={680}
                        backgroundColor="#07101d"
                        nodeLabel={(node) => {
                          const esc = (value) =>
                            String(value ?? "N/A")
                              .replace(/&/g, "&amp;")
                              .replace(/</g, "&lt;")
                              .replace(/>/g, "&gt;")
                              .replace(/\"/g, "&quot;");

                          return `
                            <div class="nyayanet-node-tooltip">
                              <div class="nyayanet-tooltip-title">${esc(node.name || "Unknown")}</div>
                              <div class="nyayanet-tooltip-id">${esc(node.id || "N/A")}</div>
                              <div class="nyayanet-tooltip-divider"></div>
                              <div class="nyayanet-tooltip-grid">
                                <div><span>AGE</span><b>${esc(node.age)}</b></div>
                                <div><span>LOCATION</span><b>${esc(node.location)}</b></div>
                                <div><span>PHONE</span><b>${esc(node.phone_num)}</b></div>
                                <div><span>VEHICLE</span><b>${esc(node.vehicle_num)}</b></div>
                                <div><span>ORGANIZATION</span><b>${esc(node.org)}</b></div>
                                <div><span>CRIME RECORDED</span><b>${esc(node.crime_recorded)}</b></div>
                              </div>
                            </div>
                          `;
                        }}
                        linkLabel={(link) =>
                          `${link.relationship_type || "Potential Relationship"}${
                            link.confidence != null
                              ? ` — ${Math.round(link.confidence * 100)}% confidence`
                              : ""
                          }`
                        }
                        onNodeHover={(node) => {
                          setHoveredNode(node || null);
                        }}
                        onBackgroundClick={() => {
                          setHoveredNode(null);
                          setSelectedRelationship(null);
                        }}
                        onLinkClick={(link) => setSelectedRelationship(link)}
                        nodeCanvasObject={(node, ctx, globalScale) => {
                          const isCenter = node.is_center;
                          const isHovered = hoveredNode?.id === node.id;
                          const radius = isCenter ? 30 : 21;
                          const x = node.x || 0;
                          const y = node.y || 0;

                          ctx.save();

                          if (isCenter) {
                            ctx.beginPath();
                            ctx.arc(x, y, radius + 8, 0, 2 * Math.PI);
                            ctx.fillStyle = "rgba(31, 220, 126, 0.12)";
                            ctx.fill();
                          }

                          ctx.beginPath();
                          ctx.arc(x, y, radius, 0, 2 * Math.PI);
                          ctx.fillStyle = isCenter ? "#0b3426" : "#111f34";
                          ctx.fill();
                          ctx.lineWidth = isHovered ? 4 : (isCenter ? 3 : 2);
                          ctx.strokeStyle = isCenter ? "#25e58a" : (isHovered ? "#ffffff" : "#4f9cff");
                          ctx.stroke();

                          const initials = (node.name || "?")
                            .split(" ")
                            .map((part) => part[0])
                            .join("")
                            .slice(0, 2)
                            .toUpperCase();

                          const fontSize = Math.max(11, (isCenter ? 17 : 13) / globalScale);
                          ctx.font = `600 ${fontSize}px Inter, system-ui, sans-serif`;
                          ctx.textAlign = "center";
                          ctx.textBaseline = "middle";
                          ctx.fillStyle = "#f5f9ff";
                          ctx.fillText(initials, x, y);

                          if (globalScale > 0.65) {
                            const labelSize = Math.max(9, 12 / globalScale);
                            ctx.font = `600 ${labelSize}px Inter, system-ui, sans-serif`;
                            ctx.fillStyle = "#e8eef8";
                            ctx.fillText(node.name || "Unknown", x, y + radius + 17);

                            if (isCenter) {
                              ctx.font = `500 ${Math.max(8, 9 / globalScale)}px Inter, system-ui, sans-serif`;
                              ctx.fillStyle = "#39e79a";
                              ctx.fillText("SELECTED SUBJECT", x, y + radius + 31);
                            }
                          }

                          ctx.restore();
                        }}
                        linkCanvasObjectMode={() => "after"}
                        linkCanvasObject={(link, ctx, globalScale) => {
                          if (!link.source || !link.target) return;
                          const source = link.source;
                          const target = link.target;
                          if (typeof source.x !== "number" || typeof target.x !== "number") return;

                          const label = link.relationship_type || "Related";
                          const x = (source.x + target.x) / 2;
                          const y = (source.y + target.y) / 2;
                          const fontSize = Math.max(8, 11 / globalScale);

                          ctx.save();
                          ctx.font = `600 ${fontSize}px Inter, system-ui, sans-serif`;
                          ctx.textAlign = "center";
                          ctx.textBaseline = "middle";

                          const metrics = ctx.measureText(label);
                          const padX = 7;
                          const padY = 4;

                          ctx.fillStyle = "rgba(5, 12, 23, 0.92)";
                          ctx.strokeStyle = "rgba(98, 154, 220, 0.35)";
                          ctx.lineWidth = 1;
                          ctx.beginPath();
                          ctx.roundRect(
                            x - metrics.width / 2 - padX,
                            y - fontSize / 2 - padY,
                            metrics.width + padX * 2,
                            fontSize + padY * 2,
                            6
                          );
                          ctx.fill();
                          ctx.stroke();

                          ctx.fillStyle = "#8ec5ff";
                          ctx.fillText(label, x, y);
                          ctx.restore();
                        }}
                        nodePointerAreaPaint={(node, color, ctx) => {
                          ctx.fillStyle = color;
                          ctx.beginPath();
                          ctx.arc(node.x || 0, node.y || 0, node.is_center ? 48 : 38, 0, 2 * Math.PI);
                          ctx.fill();
                        }}
                        linkDirectionalArrowLength={7}
                        linkDirectionalArrowRelPos={0.94}
                        linkCurvature={0.08}
                        linkColor={(link) => {
                          if (selectedRelationship === link) return "#63b3ff";
                          return "rgba(82, 154, 236, 0.72)";
                        }}
                        linkWidth={(link) =>
                          selectedRelationship === link ? 3.5 : 1.6
                        }
                        linkDistance={300}
                        d3AlphaMin={0.001}
                        nodeRelSize={6}
                        warmupTicks={120}
                        cooldownTicks={360}
                        d3AlphaDecay={0.018}
                        d3VelocityDecay={0.28}
                        onEngineStop={() => {
                          if (graphRef.current) {
                            graphRef.current.zoomToFit(500, 70);
                          }
                        }}
                        enableZoomInteraction={true}
                        enablePanInteraction={true}
                      />

                      <div className="graph-controls-hint">
                        Scroll to zoom · Drag to move · Click a relationship for details
                      </div>
                    </div>
                  </div>

                  {selectedRelationship && (
                    <aside className="network-relationship-card">
                      <div className="relationship-card-header">
                        <div>
                          <span>RELATIONSHIP DETAILS</span>
                          <h3>Connection Intelligence</h3>
                        </div>
                        <button
                          type="button"
                          onClick={() => setSelectedRelationship(null)}
                          aria-label="Close relationship details"
                        >
                          ×
                        </button>
                      </div>

                      <div className="relationship-subjects">
                        <div>
                          <span>{peopleMap[selectedRelationship.source] || selectedRelationship.source}</span>
                          <small>{selectedRelationship.source}</small>
                        </div>
                        <b>↔</b>
                        <div className="relationship-subject-right">
                          <span>{peopleMap[selectedRelationship.target] || selectedRelationship.target}</span>
                          <small>{selectedRelationship.target}</small>
                        </div>
                      </div>

                      <div className="relationship-badge-row">
                        <strong>{selectedRelationship.relationship_type || "Potential Relationship"}</strong>
                        {selectedRelationship.confidence != null && (
                          <span>{Math.round(selectedRelationship.confidence * 100)}% Confidence</span>
                        )}
                      </div>

                      <div className="relationship-metrics-grid">
                        <div><span>PHONE CALLS</span><strong>{selectedRelationship.calls || 0}</strong></div>
                        <div><span>TRANSACTIONS</span><strong>{selectedRelationship.transactions || 0}</strong></div>
                        <div><span>MEETINGS</span><strong>{selectedRelationship.meetings || 0}</strong></div>
                        <div><span>TOTAL VALUE</span><strong>₹{Number(selectedRelationship.total_transaction_amount || 0).toLocaleString("en-IN")}</strong></div>
                      </div>

                      <div className="relationship-evidence-block">
                        <span>EVIDENCE SUMMARY</span>
                        <p>
                          {selectedRelationship.relationship_description ||
                            selectedRelationship.reason ||
                            "No relationship explanation available."}
                        </p>
                      </div>
                    </aside>
                  )}
                </div>
              )}

              <div className="network-footer-note">
                <span className="network-footer-info">i</span>
                Hover over any person node to view profile information. Click relationship lines to inspect communication, transaction and meeting evidence.
              </div>
            </>
          )}
        </section>

      </main>

      {/* ========================================================
          CREATE INVESTIGATION MODAL
      ======================================================== */}

      {showCreateModal && (
        <div
          className="modal-backdrop"
          onClick={() =>
            setShowCreateModal(false)
          }
        >

          <div
            className="modal"
            onClick={(e) =>
              e.stopPropagation()
            }
          >

            <div className="modal-header">

              <div>
                <div className="eyebrow">
                  NEW CASE
                </div>

                <h2>
                  Create Investigation
                </h2>

                <p className="muted">
                  Create a secure investigation workspace.
                </p>
              </div>

              <button
                className="modal-close"
                onClick={() =>
                  setShowCreateModal(false)
                }
              >
                ×
              </button>

            </div>

            <div className="form-group">

              <label>
                Investigation Title
              </label>

              <input
                type="text"
                placeholder="e.g. Operation Red Lotus"
                value={newTitle}
                onChange={(e) =>
                  setNewTitle(e.target.value)
                }
              />

            </div>

            <div className="form-group">

              <label>
                Description
              </label>

              <textarea
                rows={6}
                placeholder="Describe the purpose and scope of this investigation..."
                value={newDescription}
                onChange={(e) =>
                  setNewDescription(
                    e.target.value
                  )
                }
              />

            </div>

            <div className="modal-actions">

              <button
                className="ghost"
                onClick={() =>
                  setShowCreateModal(false)
                }
              >
                Cancel
              </button>

              <button
                onClick={createInvestigation}
                disabled={
                  creating ||
                  !newTitle.trim()
                }
              >
                {creating
                  ? "Creating..."
                  : "Create Investigation"}
              </button>

            </div>

          </div>

        </div>
      )}

    </div>
  );
}