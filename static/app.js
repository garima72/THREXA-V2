let graphData = null;
let cy = null;
let selectedNode = null;

function $(id) { return document.getElementById(id); }

function escapeHtml(str) {
  var s = String(str == null ? "" : str);
  s = s.split("&").join("&amp;");
  s = s.split("<").join("&lt;");
  s = s.split(">").join("&gt;");
  s = s.split('"').join("&quot;");
  s = s.split("'").join("&#39;");
  return s;
}

async function getJSON(url) {
  const res = await fetch(url);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || "Request failed");
  return data;
}

function nodeColor(type, criticality) {
  if (criticality === "critical") return "#ef817b";
  const map = {
    user: "#80b9df",
    device: "#a7e3c2",
    server: "#f2b56b",
    application: "#d7a5e8",
    database: "#c084fc",
    business_service: "#7dd3fc",
    ip: "#ef817b"
  };
  return map[type] || "#91a39f";
}

function buildCyElements() {
  const nodes = graphData.nodes.map(n => ({
    data: { id: n.id, label: n.label, type: n.type, criticality: n.criticality, description: n.description }
  }));
  const edges = graphData.edges.map((e, i) => ({
    data: {
      id: e.source + "|" + e.target + "|" + i,
      source: e.source,
      target: e.target,
      label: e.relation,
      relation: e.relation
    }
  }));
  return nodes.concat(edges);
}

function initCytoscape() {
  if (cy) cy.destroy();
  cy = cytoscape({
    container: $("cy"),
    elements: buildCyElements(),
    style: [
      {
        selector: "node",
        style: {
          "background-color": function(ele) {
            return nodeColor(ele.data("type"), ele.data("criticality"));
          },
          "label": "data(label)",
          "color": "#e9f0ed",
          "font-size": "10px",
          "text-valign": "bottom",
          "text-halign": "center",
          "text-margin-y": 6,
          "text-wrap": "wrap",
          "text-max-width": 90,
          "width": 36,
          "height": 36,
          "border-width": 2,
          "border-color": "#1a2529"
        }
      },
      {
        selector: "node:selected",
        style: { "border-width": 4, "border-color": "#3ecf8e" }
      },
      {
        selector: "edge",
        style: {
          "width": 1.5,
          "line-color": "#3a4a50",
          "target-arrow-color": "#3a4a50",
          "target-arrow-shape": "triangle",
          "curve-style": "bezier",
          "label": "data(label)",
          "font-size": "8px",
          "color": "#8aa09a",
          "text-rotation": "autorotate",
          "text-margin-y": -8
        }
      },
      {
        selector: ".highlighted",
        style: { "background-color": "#3ecf8e", "border-color": "#3ecf8e", "border-width": 3 }
      },
      {
        selector: ".path",
        style: { "background-color": "#f2b56b", "line-color": "#f2b56b", "target-arrow-color": "#f2b56b", "width": 3 }
      }
    ],
    layout: { name: "cose", animate: false, padding: 30, nodeRepulsion: 8000, idealEdgeLength: 90 }
  });

  cy.on("tap", "node", function(evt) {
    selectedNode = evt.target.id();
    const n = graphData.nodes.find(function(x) { return x.id === selectedNode; });
    $("selectedLabel").textContent = n ? (n.label + " (" + n.id + ") — " + n.criticality) : selectedNode;
    $("sourceSelect").value = selectedNode;
    $("pathSource").value = selectedNode;
  });
}

function populateSelects() {
  const options = graphData.nodes.map(function(n) {
    return '<option value="' + n.id + '">' + escapeHtml(n.label) + " (" + n.id + ")</option>";
  }).join("");
  $("sourceSelect").innerHTML = options;
  $("pathSource").innerHTML = options;
  $("pathTarget").innerHTML = options;
  const critical = graphData.nodes.find(function(n) { return n.id === "DB01"; });
  if (critical) $("pathTarget").value = "DB01";
}

function highlightNodes(ids, cls) {
  cls = cls || "highlighted";
  cy.elements().removeClass("highlighted path");
  ids.forEach(function(id) { cy.getElementById(id).addClass(cls); });
  if (ids.length) cy.fit(cy.nodes().filter(function(n) { return ids.indexOf(n.id()) !== -1; }), 60);
}

async function loadAll() {
  try {
    const status = await getJSON("/api/neo4j/status");
    const statusEl = document.querySelector(".status");
    if (statusEl) {
      if (status.connected) {
        statusEl.textContent = "Neo4j Connected (" + (status.nodes || 0) + " nodes)";
        statusEl.style.color = status.nodes > 0 ? "#3ecf8e" : "#f2b56b";
      } else {
        statusEl.textContent = "JSON Fallback";
        statusEl.style.color = "#f2b56b";
      }
    }

    graphData = await getJSON("/api/graph");
    const alertsResp = await getJSON("/api/alerts");
    const alerts = alertsResp.alerts || alertsResp;

    $("nodeCount").textContent = graphData.nodes.length;
    $("edgeCount").textContent = graphData.edges.length;
    $("alertCount").textContent = alerts.length;
    $("criticalCount").textContent = graphData.nodes.filter(function(n) { return n.criticality === "critical"; }).length;

    if (graphData.nodes.length === 0) {
      $("selectedLabel").textContent = "No nodes found. Run: python import_graph.py";
    }

    initCytoscape();
    populateSelects();

    $("alertsList").innerHTML = alerts.map(function(a) {
      return '<div class="alert-card ' + (a.severity || "") + '">' +
        "<strong>" + escapeHtml(a.title) + "</strong>" +
        "<div>" + escapeHtml(a.description) + "</div>" +
        '<div class="meta">' + (a.severity || "").toUpperCase() + " • " + (a.time || "") +
        " • Entities: " + (a.entities || []).join(", ") + "</div></div>";
    }).join("");
  } catch (err) {
    console.error(err);
    $("selectedLabel").textContent = "Failed to load data: " + err.message;
  }
}

async function runBlast() {
  const id = $("sourceSelect").value;
  const data = await getJSON("/api/blast-radius/" + id);
  const items = data.impacted.slice(0, 8).map(function(n) {
    return "<li>" + escapeHtml(n.label) + " — " + n.hops + " hop(s) (" + n.criticality + ")</li>";
  }).join("");
  $("blastResult").innerHTML = "<strong>" + data.counts.one_hop + " one-hop, " + data.counts.two_hop +
    " two-hop, " + data.counts.three_hop + " three-hop</strong><ul>" + items + "</ul><small>" + data.note + "</small>";
  highlightNodes([id].concat(data.impacted.map(function(n) { return n.id; })));
}

async function runPath() {
  const source = $("pathSource").value;
  const target = $("pathTarget").value;
  const data = await getJSON("/api/attack-path?source=" + source + "&target=" + target);
  if (!data.path || data.path.length === 0) {
    $("pathResult").innerHTML = data.message || "No path found.";
    return;
  }
  const labels = data.path.map(function(n) { return escapeHtml(n.label); }).join(" → ");
  $("pathResult").innerHTML = "<strong>" + labels + "</strong><br><small>" + data.note + "</small>";
  highlightNodes(data.path.map(function(n) { return n.id; }), "path");
}

async function runChoke() {
  const data = await getJSON("/api/choke-points");
  const items = data.items.map(function(n) {
    return "<li>" + escapeHtml(n.label) + " — score " + n.score + " (" + n.criticality + ")</li>";
  }).join("");
  $("chokeResult").innerHTML = "<ul>" + items + "</ul><small>" + data.note + "</small>";
}

async function runNext() {
  const data = await getJSON("/api/analyst/next-step");
  const rec = data.recommendation;
  if (!rec) return;
  const reasons = rec.reasons.map(function(r) { return "<li>" + escapeHtml(r) + "</li>"; }).join("");
  $("nextResult").innerHTML = "<strong>" + escapeHtml(rec.node.label) + "</strong> (score " + rec.score + ")" +
    "<ul>" + reasons + "</ul><small>" + data.explanation + "</small>";
  highlightNodes([rec.node.id]);
}

async function runIsolation() {
  const id = selectedNode || $("sourceSelect").value;
  const data = await getJSON("/api/isolation-preview/" + id);
  if (!data.affected_services.length) {
    $("isolationResult").innerHTML = "No closely dependent business services detected in the model.";
    return;
  }
  const items = data.affected_services.map(function(s) {
    return "<li>" + escapeHtml(s.service) + " (" + s.hops + " hops)</li>";
  }).join("");
  $("isolationResult").innerHTML = "<strong>Potential service impact:</strong><ul>" + items + "</ul><small>" + data.note + "</small>";
}

async function showCopilot() {
  const data = await getJSON("/api/copilot/explain");
  $("copilotPanel").style.display = "block";
  $("copilotContent").innerHTML = "<p><strong>" + escapeHtml(data.summary) + "</strong></p>" +
    "<p>Key observations:</p><ul>" + data.key_observations.map(function(o) { return "<li>" + escapeHtml(o) + "</li>"; }).join("") + "</ul>" +
    "<p>Suggested investigation steps:</p><ul>" + data.suggested_actions.map(function(o) { return "<li>" + escapeHtml(o) + "</li>"; }).join("") + "</ul>" +
    "<small>" + escapeHtml(data.caveat) + "</small>";
  $("copilotPanel").scrollIntoView({ behavior: "smooth" });
}

function runDemo() {
  $("sourceSelect").value = "D01";
  $("pathSource").value = "D01";
  $("pathTarget").value = "DB01";
  setTimeout(runBlast, 200);
  setTimeout(runPath, 900);
  setTimeout(runNext, 1600);
  setTimeout(showCopilot, 2200);
}

document.addEventListener("DOMContentLoaded", function() {
  loadAll().catch(function(err) { console.error(err); });
  $("blastBtn").onclick = runBlast;
  $("pathBtn").onclick = runPath;
  $("chokeBtn").onclick = runChoke;
  $("nextBtn").onclick = runNext;
  $("isolationBtn").onclick = runIsolation;
  $("copilotBtn").onclick = showCopilot;
  $("demoBtn").onclick = runDemo;
  $("fitBtn").onclick = function() { if (cy) cy.fit(); };
  $("resetBtn").onclick = function() {
    if (cy) cy.elements().removeClass("highlighted path");
    $("selectedLabel").textContent = "Select a node to inspect it.";
  };
});
