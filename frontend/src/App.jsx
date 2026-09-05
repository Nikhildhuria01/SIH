import React, { useEffect, useMemo, useRef, useState } from "react";
import { supabase } from "./lib/supabase";
import ForceGraph2D from "react-force-graph-2d";

const API = import.meta.env.VITE_API_URL || "http://localhost:8080";

const SOURCE_TYPES = [
  { key: "FIR", label: "FIR / Police Complaint", icon: "📄", hint: "FIR narratives, complaint text, witness statements" },
  { key: "POLICE_REPORT", label: "Police Reports", icon: "🛡️", hint: "Case notes, investigation reports, seizure or interrogation records" },
  { key: "CDR", label: "Call Detail Records", icon: "☎", hint: "Call frequency, duration, timestamps and communication patterns" },
  { key: "FINANCIAL", label: "Financial Transactions", icon: "₹", hint: "Transaction records, account activity, payment observations" },
  { key: "SURVEILLANCE", label: "Surveillance Reports", icon: "📡", hint: "Observation logs, meetings, vehicle movement, locations" },
  { key: "SOCIAL_MEDIA", label: "Social Media Intelligence", icon: "◉", hint: "Posts, handles, mentions, messages, public interactions" },
  { key: "CRIMINAL_HISTORY", label: "Criminal History Database", icon: "⚖", hint: "Prior case references, charges, convictions or aliases" },
];

const EMPTY_SOURCE = SOURCE_TYPES.reduce((acc, source) => {
  acc[source.key] = "";
  return acc;
}, {});

function initials(name = "Unknown") {
  return name
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join("") || "U";
}

function escapeHtml(value = "") {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function apiFetch(path, options = {}, session) {
  const response = await fetch(`${API}${path}`, {
    ...options,
    headers: {
      Accept: "application/json",
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(session?.access_token
        ? { Authorization: `Bearer ${session.access_token}` }
        : {}),
      ...(options.headers || {}),
    },
  });

  const text = await response.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { detail: text };
  }

  if (!response.ok) {
    throw new Error(data?.detail || `Request failed with HTTP ${response.status}`);
  }
  return data;
}

export default function App() {
  const [session, setSession] = useState(null);
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [fullName, setFullName] = useState("");
  const [isSignup, setIsSignup] = useState(false);
  const [authLoading, setAuthLoading] = useState(false);

  const [investigations, setInvestigations] = useState([]);
  const [selected, setSelected] = useState(null);
  const [investigationFilter, setInvestigationFilter] = useState("active");

  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newTitle, setNewTitle] = useState("");
  const [newDescription, setNewDescription] = useState("");
  const [newSources, setNewSources] = useState({ ...EMPTY_SOURCE });
  const [newFirLanguage, setNewFirLanguage] = useState("en");
  const [creating, setCreating] = useState(false);

  const [sourceDrafts, setSourceDrafts] = useState({ ...EMPTY_SOURCE });
  const [sourceLanguage, setSourceLanguage] = useState("en");
  const [analysisLoading, setAnalysisLoading] = useState(false);
  const [analysis, setAnalysis] = useState(null);

  const [firText, setFirText] = useState("");
  const [firEntities, setFirEntities] = useState([]);
  const [firAnalyzing, setFirAnalyzing] = useState(false);
  const [tipText, setTipText] = useState("");
  const [tipResult, setTipResult] = useState(null);
  const [tipAnalyzing, setTipAnalyzing] = useState(false);

  const [criminalSearch, setCriminalSearch] = useState("");
  const [criminalResults, setCriminalResults] = useState([]);
  const [searchLoading, setSearchLoading] = useState(false);
  const [showSearchResults, setShowSearchResults] = useState(false);
  const [selectedCriminal, setSelectedCriminal] = useState(null);
  const [analysisGraph, setAnalysisGraph] = useState({ nodes: [], links: [] });
  const [graph, setGraph] = useState({ nodes: [], links: [] });
  const [graphLoading, setGraphLoading] = useState(false);
  const [selectedRelationship, setSelectedRelationship] = useState(null);
  const [hoveredNode, setHoveredNode] = useState(null);
  const [hoveredLink, setHoveredLink] = useState(null);
  const graphRef = useRef(null);
  // Tracks whose session is currently active so the auth listener below can
  // tell "same investigator, token silently refreshed" apart from "a
  // different investigator actually signed in".
  const sessionUserIdRef = useRef(null);

  useEffect(() => {
    let mounted = true;

    const initialize = async () => {
      try {
        setLoading(true);
        const {
          data: { session: currentSession },
        } = await supabase.auth.getSession();
        if (!mounted) return;
        setSession(currentSession);
        sessionUserIdRef.current = currentSession?.user?.id || null;
        if (currentSession) await loadProfile(currentSession.user.id);
      } catch (err) {
        if (mounted) setError(err.message || "Unable to initialize application.");
      } finally {
        if (mounted) setLoading(false);
      }
    };

    initialize();

    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((event, nextSession) => {
      // Supabase re-validates the session (and re-fires SIGNED_IN /
      // TOKEN_REFRESHED) whenever the browser tab regains focus. That is
      // NOT a real login or logout — treating every event as one was why
      // switching tabs reset the whole workspace and lost in-progress
      // investigation work. Only a genuine sign-out, or a different
      // investigator signing in, should clear state.
      if (event === "SIGNED_OUT" || !nextSession) {
        sessionUserIdRef.current = null;
        setSession(null);
        setProfile(null);
        setInvestigations([]);
        setSelected(null);
        resetCaseState();
        return;
      }

      const nextUserId = nextSession.user?.id || null;
      const isDifferentUser = nextUserId !== sessionUserIdRef.current;
      sessionUserIdRef.current = nextUserId;

      // Always keep the session (and its access_token) current so API
      // calls don't start using a stale token after a silent refresh.
      setSession(nextSession);

      if (isDifferentUser) {
        setProfile(null);
        setInvestigations([]);
        setSelected(null);
        resetCaseState();
        setTimeout(() => loadProfile(nextSession.user.id), 0);
      }
      // Same investigator, just a refreshed token: nothing else resets,
      // so the active investigation, drafts, analysis and graph survive
      // a tab switch untouched.
    });

    return () => {
      mounted = false;
      subscription.unsubscribe();
    };
  }, []);

  async function loadProfile(userId) {
    try {
      const { data, error: profileError } = await supabase
        .from("profiles")
        .select("*")
        .eq("id", userId)
        .maybeSingle();
      if (profileError) throw profileError;
      setProfile(data);
      if (data?.is_authorized) await loadInvestigations();
    } catch (err) {
      setError(err.message || "Unable to load profile.");
    }
  }

  async function loadInvestigations() {
    const { data, error: investigationsError } = await supabase
      .from("investigations")
      .select("*")
      .order("created_at", { ascending: false });
    if (investigationsError) throw investigationsError;
    setInvestigations(data || []);
    if (data?.length && !selected) setSelected(data[0]);
  }

  async function handleAuth(event) {
    event.preventDefault();
    setError("");
    if (!email.trim() || !password.trim()) {
      setError("Email and password are required.");
      return;
    }
    setAuthLoading(true);
    try {
      if (isSignup) {
        const { data, error: signUpError } = await supabase.auth.signUp({
          email: email.trim(),
          password,
          options: { data: { full_name: fullName.trim() } },
        });
        if (signUpError) throw signUpError;
        if (data.user && !data.session) {
          alert("Account created. Verify your email if confirmation is enabled.");
        }
      } else {
        const { data, error: signInError } = await supabase.auth.signInWithPassword({
          email: email.trim(),
          password,
        });
        if (signInError) throw signInError;
        if (data.session) {
          setSession(data.session);
          await loadProfile(data.session.user.id);
        }
      }
    } catch (err) {
      setError(err.message || "Authentication failed.");
    } finally {
      setAuthLoading(false);
    }
  }

  function resetCaseState() {
    setAnalysis(null);
    setFirText("");
    setFirEntities([]);
    setTipText("");
    setTipResult(null);
    setCriminalSearch("");
    setCriminalResults([]);
    setShowSearchResults(false);
    setSelectedCriminal(null);
    setSelectedRelationship(null);
    setHoveredNode(null);
    setHoveredLink(null);
    setAnalysisGraph({ nodes: [], links: [] });
    setGraph({ nodes: [], links: [] });
    setSourceDrafts({ ...EMPTY_SOURCE });
  }

  async function createInvestigation(event) {
    event.preventDefault();
    setError("");
    if (!newTitle.trim()) {
      setError("Investigation title is required.");
      return;
    }
    const filledSources = SOURCE_TYPES.filter((source) => newSources[source.key]?.trim());
    if (filledSources.length === 0) {
      setError("Add at least one intelligence source before starting the investigation.");
      return;
    }

    setCreating(true);
    try {
      const created = await apiFetch(
        "/api/investigations",
        {
          method: "POST",
          body: JSON.stringify({
            title: newTitle.trim(),
            description: newDescription.trim(),
          }),
        },
        session
      );

      setInvestigations((prev) => [created, ...prev]);
      setSelected(created);
      setShowCreateModal(false);
      setNewTitle("");
      setNewDescription("");
      setNewSources({ ...EMPTY_SOURCE });
      resetCaseState();

      const sources = filledSources.map((source) => ({
        source_type: source.key,
        title: source.label,
        content: newSources[source.key],
        language: source.key === "FIR" ? newFirLanguage : "en",
      }));

      const result = await apiFetch(
        `/api/investigations/${created.id}/analyze-sources`,
        { method: "POST", body: JSON.stringify({ sources }) },
        session
      );
      setAnalysis(result);
      setAnalysisGraph(result.graph || { nodes: [], links: [] });
      setGraph(result.graph || { nodes: [], links: [] });
      await loadInvestigations();
    } catch (err) {
      setError(err.message || "Unable to start investigation.");
    } finally {
      setCreating(false);
    }
  }

  async function analyzeSourcesForExistingCase() {
    if (!selected) return;
    const filled = SOURCE_TYPES.filter((source) => sourceDrafts[source.key]?.trim());
    if (filled.length === 0) {
      setError("Add at least one source before running analysis.");
      return;
    }
    setAnalysisLoading(true);
    setError("");
    try {
      const sources = filled.map((source) => ({
        source_type: source.key,
        title: source.label,
        content: sourceDrafts[source.key],
        language: source.key === "FIR" ? sourceLanguage : "en",
      }));
      const result = await apiFetch(
        `/api/investigations/${selected.id}/analyze-sources`,
        { method: "POST", body: JSON.stringify({ sources }) },
        session
      );
      setAnalysis(result);
      setAnalysisGraph(result.graph || { nodes: [], links: [] });
      setGraph(result.graph || { nodes: [], links: [] });
      setSourceDrafts({ ...EMPTY_SOURCE });
      await loadInvestigations();
    } catch (err) {
      setError(err.message || "Source analysis failed.");
    } finally {
      setAnalysisLoading(false);
    }
  }

  async function analyzeFIR() {
    if (!selected || !firText.trim()) {
      setError("Select an investigation and enter FIR text.");
      return;
    }
    setFirAnalyzing(true);
    setError("");
    try {
      const data = await apiFetch(
        "/api/nlp/extract",
        {
          method: "POST",
          body: JSON.stringify({
            investigation_id: selected.id,
            source_type: "FIR",
            title: "Standalone FIR Analysis",
            content: firText,
            language: sourceLanguage,
          }),
        },
        session
      );
      const entities = [];
      Object.entries(data.entities || {}).forEach(([label, values]) => {
        if (Array.isArray(values)) values.forEach((value) => entities.push({ label, text: value }));
      });
      setFirEntities(entities);
    } catch (err) {
      setError(err.message || "FIR analysis failed.");
    } finally {
      setFirAnalyzing(false);
    }
  }

  async function analyzeTip() {
    if (!selected || !tipText.trim()) {
      setError("Select an investigation and enter a tip.");
      return;
    }
    setTipAnalyzing(true);
    setError("");
    try {
      const result = await apiFetch(
        "/api/tips/analyze",
        { method: "POST", body: JSON.stringify({ investigation_id: selected.id, text: tipText }) },
        session
      );
      setTipResult(result);
    } catch (err) {
      setError(err.message || "Tip analysis failed.");
    } finally {
      setTipAnalyzing(false);
    }
  }

  // Search within the graph generated for THIS investigation.
  // No training dataset or global person database is queried here.
  useEffect(() => {
    const query = criminalSearch.trim().toLowerCase();

    if (!query) {
      setCriminalResults([]);
      setShowSearchResults(false);
      return undefined;
    }

    const matches = (analysisGraph.nodes || [])
      .filter((person) => {
        const haystack = [
          person.name,
          person.id,
          person.phone_num,
          person.vehicle_num,
          person.org,
          person.location,
        ]
          .filter(Boolean)
          .join(' ')
          .toLowerCase();
        return haystack.includes(query);
      })
      .slice(0, 10);

    setCriminalResults(matches);
    setShowSearchResults(true);
    setSearchLoading(false);

    return undefined;
  }, [criminalSearch, analysisGraph]);

  function selectCriminal(person) {
    if (!person) return;

    setSelectedCriminal(person);
    setCriminalSearch(person.name || '');
    setCriminalResults([]);
    setShowSearchResults(false);
    setSelectedRelationship(null);

    const relatedIds = new Set([person.id]);
    const relatedLinks = (analysisGraph.links || []).filter((link) => {
      const sourceId = typeof link.source === 'object' ? link.source.id : link.source;
      const targetId = typeof link.target === 'object' ? link.target.id : link.target;
      const connected = sourceId === person.id || targetId === person.id;
      if (connected) {
        relatedIds.add(sourceId);
        relatedIds.add(targetId);
      }
      return connected;
    });

    setGraph({
      nodes: (analysisGraph.nodes || []).filter((node) => relatedIds.has(node.id)),
      links: relatedLinks,
    });
  }

  function resetGraphView() {
    setSelectedCriminal(null);
    setSelectedRelationship(null);
    setGraph(analysisGraph || { nodes: [], links: [] });
    setCriminalSearch('');
    setCriminalResults([]);
    setShowSearchResults(false);
  }

  useEffect(() => {
    if (!selected || !session?.access_token) return;

    let cancelled = false;

    async function loadPersistedAnalysis() {
      try {
        const result = await apiFetch(
          `/api/investigations/${selected.id}/analysis`,
          {},
          session
        );
        if (cancelled) return;

        setAnalysisGraph(result.graph || { nodes: [], links: [] });
        setGraph(result.graph || { nodes: [], links: [] });
        setSelectedCriminal(null);
        setSelectedRelationship(null);

        setAnalysis((previous) => ({
          ...(previous || {}),
          ...result,
          graph: result.graph || { nodes: [], links: [] },
        }));
      } catch (err) {
        if (!cancelled) {
          // A brand-new investigation may have no analysis yet.
          if (!String(err.message || '').includes('404')) {
            console.warn('Persisted analysis load skipped:', err.message);
          }
        }
      }
    }

    loadPersistedAnalysis();

    return () => {
      cancelled = true;
    };
  }, [selected?.id, session?.access_token]);

  useEffect(() => {
    const graphApi = graphRef.current;
    if (!graphApi) return;

    const charge = graphApi.d3Force("charge");
    const link = graphApi.d3Force("link");
    const center = graphApi.d3Force("center");

    // Large separation between people + gentle centering.
    // This is deliberately much looser than the default force layout.
    charge?.strength?.(-2600);
    charge?.distanceMax?.(1400);
    link?.distance?.(430);
    link?.strength?.(0.65);
    center?.strength?.(0.08);

    graphApi.d3ReheatSimulation?.();
  }, [graph.nodes.length, graph.links.length]);

  function closeInvestigation() {
    if (!selected) return;
    // This UI intentionally keeps case closure as an explicit state operation.
    apiFetch(`/api/investigations/${selected.id}/close`, { method: "POST" }, session)
      .then(() => loadInvestigations())
      .catch((err) => setError(err.message || "Unable to close investigation."));
  }

  async function signOut() {
    await supabase.auth.signOut();
    resetCaseState();
    setSession(null);
    setProfile(null);
    setInvestigations([]);
    setSelected(null);
  }

  const visibleInvestigations = useMemo(() => {
    return investigations.filter((item) => {
      if (investigationFilter === "all") return true;
      return item.status === investigationFilter;
    });
  }, [investigations, investigationFilter]);

  const entityTotal = analysis
    ? Object.values(analysis.entity_counts || {}).reduce((sum, value) => sum + Number(value || 0), 0)
    : 0;

  if (loading) {
    return (
      <div className="app-shell center-screen">
        <div className="loading-card">
          <div className="brand-mark large">N</div>
          <div className="eyebrow">SECURE WORKSPACE</div>
          <h1>NyayaNet</h1>
          <p>Initializing investigative intelligence environment…</p>
        </div>
      </div>
    );
  }

  if (!session) {
    return (
      <div className="app-shell center-screen">
        <div className="auth-card">
          <div className="brand-row">
            <div className="brand-mark">N</div>
            <div>
              <div className="brand-title">NyayaNet</div>
              <div className="brand-subtitle">AI-POWERED CRIMINAL NETWORK ANALYSIS</div>
            </div>
          </div>
          <div className="auth-header">
            <span className="eyebrow">AUTHORIZED ACCESS</span>
            <h1>{isSignup ? "Create Investigator Account" : "Secure Login"}</h1>
            <p>Investigative intelligence workspace for authorized personnel.</p>
          </div>
          {error && <div className="error-box">{error}</div>}
          <form onSubmit={handleAuth} className="stack-form">
            {isSignup && (
              <label>Full Name<input value={fullName} onChange={(e) => setFullName(e.target.value)} /></label>
            )}
            <label>Email<input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="investigator@example.gov" /></label>
            <label>Password<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} /></label>
            <button className="primary-button" disabled={authLoading}>{authLoading ? "Authenticating…" : isSignup ? "Create Account" : "Login Securely"}</button>
          </form>
          <button className="link-button" onClick={() => { setIsSignup((value) => !value); setError(""); }}>
            {isSignup ? "Already have an account? Login" : "Need an account? Create one"}
          </button>
        </div>
      </div>
    );
  }

  if (!profile?.is_authorized) {
    return (
      <div className="app-shell center-screen">
        <div className="auth-card restricted-card">
          <div className="restricted-icon">🔒</div>
          <span className="eyebrow">ACCESS CONTROL</span>
          <h1>Access Restricted</h1>
          <p>Your account is authenticated but is not currently authorized for the investigative workspace.</p>
          <button className="ghost-button" onClick={signOut}>Sign Out</button>
        </div>
      </div>
    );
  }

  return (
    <div className="app-shell dashboard-shell">
      <aside className="sidebar">
        <div>
          <div className="brand-row sidebar-brand">
            <div className="brand-mark">N</div>
            <div>
              <div className="brand-title">NyayaNet</div>
              <div className="brand-subtitle">INVESTIGATIVE INTELLIGENCE</div>
            </div>
          </div>

          <div className="sidebar-heading-row">
            <span>INVESTIGATIONS</span>
            <button className="small-primary" onClick={() => { setError(""); setShowCreateModal(true); }}>+ New</button>
          </div>

          <div className="filter-pills">
            {[
              ["active", "Ongoing"],
              ["closed", "Closed"],
              ["all", "All"],
            ].map(([value, label]) => (
              <button key={value} className={investigationFilter === value ? "active" : ""} onClick={() => setInvestigationFilter(value)}>
                {label}
              </button>
            ))}
          </div>

          <div className="investigation-list">
            {visibleInvestigations.length === 0 ? (
              <div className="sidebar-empty">No {investigationFilter === "all" ? "" : investigationFilter} investigations.</div>
            ) : visibleInvestigations.map((investigation) => (
              <button
                key={investigation.id}
                className={`investigation-item ${selected?.id === investigation.id ? "active" : ""}`}
                onClick={() => {
                  setSelected(investigation);
                  resetCaseState();
                }}
              >
                <span className="investigation-code">{investigation.investigation_code}</span>
                <strong>{investigation.title}</strong>
                <span className={`status-badge ${investigation.status}`}>{investigation.status}</span>
              </button>
            ))}
          </div>
        </div>

        <div className="sidebar-bottom">
          <div className="user-card">
            <div className="user-avatar">{initials(profile.full_name || session.user.email)}</div>
            <div>
              <strong>{profile.full_name || session.user.email}</strong>
              <span>{profile.role || "investigator"}</span>
            </div>
          </div>
          <button className="logout-button" onClick={signOut}>Sign Out</button>
          <div className="security-note">🔐 Authorized access • investigative actions are audited</div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div>
            <div className="eyebrow">SECURE INVESTIGATIVE WORKSPACE</div>
            <h1>Criminal Network Analysis</h1>
            <p>Collect intelligence, extract entities, discover candidate relationships, and surface suspicious patterns.</p>
          </div>
          <div className="authorized-pill"><span /> AUTHORIZED</div>
        </header>

        {error && <div className="error-box main-error"><span>{error}</span><button onClick={() => setError("")}>×</button></div>}

        {!selected ? (
          <section className="empty-dashboard panel">
            <div className="empty-icon">+</div>
            <div className="eyebrow">INVESTIGATION WORKSPACE</div>
            <h2>Start a New Investigation</h2>
            <p>Create a case, provide the available intelligence sources, and let NyayaNet build the analytical view.</p>
            <button className="primary-button compact" onClick={() => setShowCreateModal(true)}>Start New Investigation</button>
          </section>
        ) : (
          <>
            <section className="case-banner panel">
              <div>
                <div className="eyebrow">ACTIVE CASE</div>
                <h2>{selected.title}</h2>
                <p>{selected.description || "No case description provided."}</p>
              </div>
              <div className="case-meta">
                <span>INVESTIGATION ID</span>
                <strong>{selected.investigation_code}</strong>
                <button className="ghost-button small" onClick={closeInvestigation} disabled={selected.status === "closed"}>
                  {selected.status === "closed" ? "Investigation Closed" : "Close Investigation"}
                </button>
              </div>
            </section>

            <section className="stats-grid">
              <div className="stat-card"><span>SOURCES PROCESSED</span><strong>{analysis?.sources?.length || 0}</strong><small>documents in this analysis</small></div>
              <div className="stat-card"><span>ENTITIES EXTRACTED</span><strong>{entityTotal}</strong><small>people, places, vehicles & more</small></div>
              <div className="stat-card"><span>CANDIDATE LINKS</span><strong>{analysis?.candidate_relationships?.length || 0}</strong><small>model-scored analytical leads</small></div>
              <div className="stat-card alert-stat"><span>SUSPICIOUS PATTERNS</span><strong>{analysis?.suspicious_patterns?.length || 0}</strong><small>requires investigator review</small></div>
            </section>

            {analysis?.warnings?.length > 0 && (
              <div className="error-box main-error analysis-warning">
                <span>{analysis.warnings.join(" ")}</span>
                <button onClick={() => setAnalysis((prev) => (prev ? { ...prev, warnings: [] } : prev))}>×</button>
              </div>
            )}

            <section className="panel source-panel">
              <div className="section-header">
                <div>
                  <div className="eyebrow">DATA INGESTION</div>
                  <h2>Add Intelligence Sources</h2>
                  <p>Provide available intelligence. The system keeps the original text, extracts entities, and builds candidate evidence across sources.</p>
                </div>
                <div className="pipeline-badge">INGEST → NLP → GRAPH → ANALYTICS</div>
              </div>

              <div className="source-grid">
                {SOURCE_TYPES.map((source) => (
                  <div className="source-card" key={source.key}>
                    <div className="source-card-head">
                      <span className="source-icon">{source.icon}</span>
                      <div><strong>{source.label}</strong><small>{source.hint}</small></div>
                    </div>
                    <textarea
                      rows={5}
                      placeholder={`Paste ${source.label.toLowerCase()} here…`}
                      value={sourceDrafts[source.key]}
                      onChange={(e) => setSourceDrafts((prev) => ({ ...prev, [source.key]: e.target.value }))}
                    />
                    {source.key === "FIR" && (
                      <select value={sourceLanguage} onChange={(e) => setSourceLanguage(e.target.value)}>
                        <option value="en">FIR language: English</option>
                        <option value="hi">FIR language: Hindi</option>
                        <option value="pa">FIR language: Punjabi</option>
                      </select>
                    )}
                  </div>
                ))}
              </div>

              <div className="source-actions">
                <button className="primary-button" onClick={analyzeSourcesForExistingCase} disabled={analysisLoading}>
                  {analysisLoading ? "Running Intelligence Analysis…" : "Run Intelligence Analysis"}
                </button>
                <span>At least one source is required. Add only the sources available for the case.</span>
              </div>
            </section>

            <section className="analytics-grid">
              <div className="panel analysis-card">
                <div className="section-header compact-header"><div><div className="eyebrow">NETWORK INTELLIGENCE</div><h2>Influential Individuals</h2></div></div>
                <div className="rank-list">
                  {(analysis?.influential_persons || []).slice(0, 6).map((person, index) => (
                    <div className="rank-row" key={person.person_id}>
                      <span className="rank-number">{index + 1}</span>
                      <div><strong>{person.name}</strong><small>{person.person_id}</small></div>
                      <div className="rank-score">{Math.round((person.influence_score || 0) * 100)}<small>influence</small></div>
                    </div>
                  ))}
                  {!analysis?.influential_persons?.length && <div className="empty-inline">Run intelligence analysis to identify network-central individuals.</div>}
                </div>
              </div>

              <div className="panel analysis-card">
                <div className="section-header compact-header"><div><div className="eyebrow">PATTERN DETECTION</div><h2>Suspicious Activity Signals</h2></div></div>
                <div className="pattern-list">
                  {(analysis?.suspicious_patterns || []).slice(0, 6).map((pattern, index) => (
                    <div className="pattern-row" key={`${pattern.person_a_id}-${pattern.person_b_id}-${index}`}>
                      <div className="pattern-icon">!</div>
                      <div><strong>{pattern.person_a_id} ↔ {pattern.person_b_id}</strong><small>{(pattern.reasons || []).join(" • ") || "Unusual activity combination"}</small></div>
                      <span>{Math.round((pattern.confidence || 0) * 100)}%</span>
                    </div>
                  ))}
                  {!analysis?.suspicious_patterns?.length && <div className="empty-inline">No suspicious combinations surfaced yet.</div>}
                </div>
              </div>
            </section>

            <section className="panel network-workspace">
              <div className="section-header">
                <div>
                  <div className="eyebrow">NETWORK INTELLIGENCE</div>
                  <h2>Criminal Network Explorer</h2>
                  <p>NyayaNet builds this network automatically from the intelligence submitted to this investigation. Search is used to focus the generated network on a subject.</p>
                </div>
                <div className="legend"><span><i className="legend-dot selected" /> Selected Subject</span><span><i className="legend-dot connected" /> Connected Person</span><span>Hover a node for profile details</span></div>
              </div>

              <div className="network-topbar">
                <div className="search-panel">
                  <label>FOCUS WITHIN GENERATED NETWORK</label>
                  <div className="search-input-wrap">
                    <span>⌕</span>
                    <input
                      value={criminalSearch}
                      placeholder="Search a person from this investigation…"
                      onChange={(e) => setCriminalSearch(e.target.value)}
                      onFocus={() => criminalResults.length && setShowSearchResults(true)}
                    />
                    {criminalSearch && <button onClick={resetGraphView}>×</button>}
                    {searchLoading && <em>Searching…</em>}
                  </div>
                  {showSearchResults && (
                    <div className="search-results">
                      <div className="search-results-title">MATCHING RECORDS <span>{criminalResults.length}</span></div>
                      {criminalResults.length ? criminalResults.map((person) => (
                        <button key={person.id} className="search-result-row" onClick={() => selectCriminal(person)}>
                          <div className="result-avatar">{initials(person.name)}</div>
                          <div className="result-main"><strong>{person.name}</strong><small>{person.person_id} · {person.location || "Location unavailable"}</small><span>☎ {person.phone_num || "No phone"}</span></div>
                          <span className="result-arrow">›</span>
                        </button>
                      )) : <div className="empty-inline">No matching person found.</div>}
                    </div>
                  )}
                </div>

                {selectedCriminal && (
                  <div className="subject-summary">
                    <div className="subject-avatar">{initials(selectedCriminal.name)}</div>
                    <div className="subject-main"><span>SELECTED SUBJECT</span><strong>{selectedCriminal.name}</strong><small>{selectedCriminal.person_id} · {selectedCriminal.location || "Location unavailable"}</small></div>
                    <div className="subject-metric"><span>AGE</span><strong>{selectedCriminal.age || "—"}</strong></div>
                    <div className="subject-metric"><span>CONNECTIONS</span><strong>{selectedCriminal ? Math.max(0, graph.nodes.length - 1) : analysisGraph.links.length}</strong></div>
                    <div className="subject-metric"><span>PHONE</span><strong>{selectedCriminal.phone_num || "—"}</strong></div>
                    <div className="subject-metric"><span>VEHICLE</span><strong>{selectedCriminal.vehicle_num || "—"}</strong></div>
                  </div>
                )}
              </div>

              <div className={`network-body ${selectedRelationship ? "with-details" : ""}`}>
                <div className="graph-panel">
                  <div className="graph-titlebar"><div><span>RELATIONSHIP MAP</span><strong>{selectedCriminal ? `${Math.max(0, graph.nodes.length - 1)} connections in focus` : `${analysisGraph.links.length} candidate connections generated from submitted evidence`}</strong></div><button className="ghost-button small" onClick={() => { resetGraphView(); setTimeout(() => graphRef.current?.zoomToFit?.(500, 80), 0); }}>Reset View</button></div>
                  <div className="graph-canvas">
                    {graphLoading ? (
                      <div className="graph-placeholder"><div className="spinner" /><h3>Building subject network…</h3><p>Combining relationship records and model signals.</p></div>
                    ) : graph.nodes.length === 0 ? (
                      <div className="graph-placeholder"><div className="placeholder-icon">◌</div><h3>No network generated yet</h3><p>Submit at least one intelligence source and run analysis. The graph is generated only from this investigation's submitted evidence.</p></div>
                    ) : (
                      <ForceGraph2D
                        ref={graphRef}
                        graphData={graph}
                        backgroundColor="#06101f"
                        enableNodeDrag
                        cooldownTicks={420}
                        warmupTicks={120}
                        d3AlphaDecay={0.009}
                        d3VelocityDecay={0.18}
                        nodeAutoColorBy="is_center"
                        nodeRelSize={7}

                        // Node hover uses the library's cursor-following tooltip.
                        // No fixed-position detail card is used.
                        nodeLabel={(node) => `
                          <div class="node-tooltip">
                            <div class="node-tooltip-head">
                              <div class="node-tooltip-avatar">
                                ${escapeHtml(initials(node.name))}
                              </div>
                              <div>
                                <strong>${escapeHtml(node.name || "Unknown")}</strong>
                                <span>Person</span>
                              </div>
                            </div>

                            <div class="node-tooltip-grid">
                              <div><span>AGE</span><b>${escapeHtml(node.age ?? "—")}</b></div>
                              <div><span>LOCATION</span><b>${escapeHtml(node.location || "—")}</b></div>
                              <div><span>PHONE</span><b>${escapeHtml(node.phone_num || "—")}</b></div>
                              <div><span>VEHICLE</span><b>${escapeHtml(node.vehicle_num || "—")}</b></div>
                              <div><span>ORGANIZATION</span><b>${escapeHtml(node.org || "—")}</b></div>
                              <div><span>CRIME RECORDED</span><b>${escapeHtml(node.crime_recorded || "—")}</b></div>
                              <div><span>SOURCES</span><b>${escapeHtml((node.source_types || []).join(" • ") || "—")}</b></div>
                            </div>
                          </div>
                        `}

                        // Relationship hover also follows the cursor.
                        linkLabel={(link) => `
                          <div class="edge-tooltip">
                            <strong>
                              ${escapeHtml(
                                link.relationship_type ||
                                "Evidence-linked Association"
                              )}
                            </strong>
                            ${
                              link.confidence != null
                                ? `<span>Potential score: ${Math.round(
                                    link.confidence * 100
                                  )}%</span>`
                                : ""
                            }
                            <p>
                              ${escapeHtml(
                                link.relationship_description ||
                                link.reason ||
                                "Evidence-backed relationship."
                              )}
                            </p>
                            <div class="edge-evidence">
                              ${
                                Number(link.calls || 0) > 0
                                  ? `<span>☎ ${Number(link.calls)} call(s)</span>`
                                  : ""
                              }
                              ${
                                Number(link.transactions || 0) > 0
                                  ? `<span>₹ ${Number(link.transactions)} transaction(s)</span>`
                                  : ""
                              }
                              ${
                                Number(link.meetings || 0) > 0
                                  ? `<span>● ${Number(link.meetings)} meeting(s)</span>`
                                  : ""
                              }
                            </div>
                          </div>
                        `}

                        nodeCanvasObject={(node, ctx, globalScale) => {
                          const isHovered = hoveredNode === node;
                          const isCenter = Boolean(node.is_center);

                          const radius = isHovered ? 17 : 13;

                          ctx.save();

                          if (isHovered || isCenter) {
                            ctx.beginPath();
                            ctx.arc(
                              node.x,
                              node.y,
                              radius + 8,
                              0,
                              Math.PI * 2
                            );
                            ctx.fillStyle = isCenter
                              ? "rgba(46, 232, 137, 0.14)"
                              : "rgba(74, 165, 255, 0.12)";
                            ctx.fill();
                          }

                          ctx.beginPath();
                          ctx.arc(
                            node.x,
                            node.y,
                            radius,
                            0,
                            Math.PI * 2
                          );
                          ctx.fillStyle = isCenter
                            ? "#073a2d"
                            : "#102944";
                          ctx.fill();

                          ctx.strokeStyle = isCenter
                            ? "#2ee889"
                            : isHovered
                              ? "#b7dcff"
                              : "#4aa5ff";
                          ctx.lineWidth = isHovered ? 3 : 2;
                          ctx.stroke();

                          // Initials inside the person node.
                          ctx.font =
                            "700 11px Inter, system-ui, sans-serif";
                          ctx.fillStyle = "#f5f9ff";
                          ctx.textAlign = "center";
                          ctx.textBaseline = "middle";
                          ctx.fillText(
                            initials(node.name),
                            node.x,
                            node.y
                          );

                          // Full PERSON NAME below the node.
                          // No IDs, relationship types, locations, or other
                          // entities are rendered on the graph itself.
                          const name = node.name || "Unknown";
                          const nameSize = Math.max(
                            10,
                            Math.min(
                              14,
                              12 / Math.max(globalScale, 0.75)
                            )
                          );

                          ctx.font =
                            `600 ${nameSize}px Inter, system-ui, sans-serif`;

                          const textWidth =
                            ctx.measureText(name).width;

                          const pillWidth = textWidth + 14;
                          const pillHeight = nameSize + 10;
                          const pillY =
                            node.y + radius + 7;

                          ctx.fillStyle =
                            "rgba(4, 13, 25, 0.86)";

                          ctx.beginPath();
                          ctx.roundRect(
                            node.x - pillWidth / 2,
                            pillY,
                            pillWidth,
                            pillHeight,
                            6
                          );
                          ctx.fill();

                          ctx.fillStyle = "#eef6ff";
                          ctx.textAlign = "center";
                          ctx.textBaseline = "middle";

                          ctx.fillText(
                            name,
                            node.x,
                            pillY + pillHeight / 2
                          );

                          ctx.restore();
                        }}

                        linkWidth={(link) =>
                          hoveredLink === link
                            ? 3.5
                            : Math.max(
                                1.5,
                                1 + Number(link.confidence || 0)
                              )
                        }

                        linkColor={(link) =>
                          hoveredLink === link
                            ? "#71baff"
                            : "rgba(65, 155, 235, 0.48)"
                        }

                        linkDirectionalArrowLength={7}
                        linkDirectionalArrowRelPos={1}
                        linkCurvature={0.08}

                        onNodeHover={(node) => {
                          setHoveredNode(node || null);
                        }}

                        onLinkHover={(link) => {
                          setHoveredLink(link || null);
                        }}

                        onNodeClick={(node) => {
                          setSelectedCriminal(node);
                        }}

                        onLinkClick={(link) => {
                          setSelectedRelationship(link);
                        }}

                        onNodeDragEnd={(node) => {
                          node.fx = null;
                          node.fy = null;
                          graphRef.current?.d3ReheatSimulation?.();
                        }}

                        onEngineStop={() => {
                          graphRef.current?.zoomToFit?.(800, 120);
                        }}
                      />
                    )}
                    <div className="graph-help">Generated from current case evidence • Drag nodes • Scroll to zoom • Click a relationship for evidence details • Hover a node for profile information</div>
                  </div>
                </div>

                {selectedRelationship && (
                  <aside className="relationship-panel">
                    <div className="relationship-panel-head"><div><span className="eyebrow">RELATIONSHIP INTELLIGENCE</span><h3>Connection Details</h3></div><button onClick={() => setSelectedRelationship(null)}>×</button></div>
                    <div className="relationship-subjects">
                      <div>
                        <span>PERSON A</span>
                        <strong>
                          {graph.nodes.find((n) => n.id === (
                            typeof selectedRelationship.source === "object"
                              ? selectedRelationship.source.id
                              : selectedRelationship.source
                          ))?.name || selectedRelationship.source}
                        </strong>
                      </div>
                      <div className="relationship-arrow">↔</div>
                      <div>
                        <span>PERSON B</span>
                        <strong>
                          {graph.nodes.find((n) => n.id === (
                            typeof selectedRelationship.target === "object"
                              ? selectedRelationship.target.id
                              : selectedRelationship.target
                          ))?.name || selectedRelationship.target}
                        </strong>
                      </div>
                    </div>
                    <div className="relationship-type-block"><span>RELATIONSHIP TYPE</span><strong>{selectedRelationship.relationship_type || "Potential Relationship"}</strong><em>{selectedRelationship.confidence != null ? `${Math.round(selectedRelationship.confidence * 100)}% analytical confidence` : "Confidence unavailable"}</em></div>
                    <div className="relationship-metrics"><div><span>PHONE CALLS</span><strong>{selectedRelationship.calls || 0}</strong></div><div><span>TRANSACTIONS</span><strong>{selectedRelationship.transactions || 0}</strong></div><div><span>MEETINGS</span><strong>{selectedRelationship.meetings || 0}</strong></div><div><span>TRANSACTION VALUE</span><strong>₹{Number(selectedRelationship.total_transaction_amount || 0).toLocaleString("en-IN")}</strong></div></div>
                    <div className="relationship-evidence"><span>EVIDENCE EXPLANATION</span><p>{selectedRelationship.relationship_description || selectedRelationship.reason || "No explanation is available for this candidate link."}</p></div>
                    <div className="lead-warning">Analytical lead only. This score does not establish criminal guilt or prove the stated relationship.</div>
                  </aside>
                )}
              </div>
            </section>

            <section className="utility-grid">
              <div className="panel">
                <div className="section-header compact-header"><div><div className="eyebrow">NLP ENGINE</div><h2>Standalone FIR Intelligence</h2></div></div>
                <textarea className="utility-textarea" rows={7} value={firText} onChange={(e) => setFirText(e.target.value)} placeholder="Paste an additional FIR / report for focused entity extraction…" />
                <div className="utility-actions"><select value={sourceLanguage} onChange={(e) => setSourceLanguage(e.target.value)}><option value="en">English</option><option value="hi">Hindi</option><option value="pa">Punjabi</option></select><button className="primary-button" onClick={analyzeFIR} disabled={firAnalyzing}>{firAnalyzing ? "Analyzing…" : "Extract Entities"}</button></div>
                {firEntities.length > 0 && <div className="entity-list">{firEntities.map((entity, index) => <div className="entity-chip" key={`${entity.label}-${entity.text}-${index}`}><span>{entity.label}</span><strong>{entity.text}</strong></div>)}</div>}
              </div>

              <div className="panel">
                <div className="section-header compact-header"><div><div className="eyebrow">INTELLIGENCE SEED</div><h2>Tip → Network</h2></div></div>
                <textarea className="utility-textarea" rows={7} value={tipText} onChange={(e) => setTipText(e.target.value)} placeholder="Enter a small tip or lead…" />
                <button className="primary-button" onClick={analyzeTip} disabled={tipAnalyzing}>{tipAnalyzing ? "Analyzing…" : "Analyze Tip"}</button>
                {tipResult && <pre className="tip-result">{JSON.stringify(tipResult, null, 2)}</pre>}
              </div>
            </section>

            <section className="panel methodology-panel">
              <div><div className="eyebrow">ANALYTICAL GUARDRAILS</div><h2>How NyayaNet interprets evidence</h2></div>
              <div className="guardrail-grid"><div><strong>Candidate relationship score</strong><p>Ranks evidence-backed links using observable communication, transaction, meeting and shared-entity signals.</p></div><div><strong>Suspicious pattern detection</strong><p>Flags unusual combinations of activity for investigator review; it does not declare guilt.</p></div><div><strong>Network influence</strong><p>Uses graph-centrality measures to identify structurally influential nodes, not “most criminal” people.</p></div></div>
            </section>
          </>
        )}
      </main>

      {showCreateModal && (
        <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && !creating && setShowCreateModal(false)}>
          <form className="create-modal" onSubmit={createInvestigation}>
            <div className="modal-head"><div><div className="eyebrow">NEW INVESTIGATION</div><h2>Start Investigation Workspace</h2><p>Enter the case details and all available intelligence sources. NyayaNet will process them immediately after the case is created.</p></div><button type="button" onClick={() => !creating && setShowCreateModal(false)}>×</button></div>
            <div className="modal-grid-top"><label>Investigation Title<input value={newTitle} onChange={(e) => setNewTitle(e.target.value)} placeholder="e.g. Network analysis — Sector 18" /></label><label>Case Purpose / Description<textarea rows={3} value={newDescription} onChange={(e) => setNewDescription(e.target.value)} placeholder="Scope, objective, known lead, or case summary…" /></label></div>
            <div className="modal-source-header"><div><span>INTELLIGENCE SOURCES</span><small>Provide the sources available for this case. FIR is not the only accepted input.</small></div><select value={newFirLanguage} onChange={(e) => setNewFirLanguage(e.target.value)}><option value="en">FIR: English</option><option value="hi">FIR: Hindi</option><option value="pa">FIR: Punjabi</option></select></div>
            <div className="modal-source-grid">{SOURCE_TYPES.map((source) => <div className="modal-source-card" key={source.key}><div><span>{source.icon}</span><strong>{source.label}</strong></div><textarea rows={4} value={newSources[source.key]} onChange={(e) => setNewSources((prev) => ({ ...prev, [source.key]: e.target.value }))} placeholder={`Enter ${source.label.toLowerCase()}…`} /></div>)}</div>
            <div className="modal-foot"><span>At least one source must be supplied. Original evidence is stored with an integrity hash.</span><div><button type="button" className="ghost-button" onClick={() => setShowCreateModal(false)} disabled={creating}>Cancel</button><button type="submit" className="primary-button" disabled={creating}>{creating ? "Creating & Analyzing…" : "Create & Analyze Investigation"}</button></div></div>
          </form>
        </div>
      )}
    </div>
  );
}
