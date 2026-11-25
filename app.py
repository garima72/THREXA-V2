from flask import Flask, jsonify, render_template, request, session, redirect
from pathlib import Path
from collections import defaultdict
import json
import os
import networkx as nx
from dotenv import load_dotenv
from neo4j_store import Neo4jStore
from advanced import bp as advanced_bp

load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv('THREXA_SECRET_KEY', 'change-this-secret-before-deployment')
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax')
BASE = Path(__file__).resolve().parent
store = Neo4jStore()
app.register_blueprint(advanced_bp)



@app.before_request
def require_login():
    if request.endpoint == 'static' or request.path.startswith('/api/auth/'):
        return None
    if not session.get('user'):
        if request.path.startswith('/api/'):
            return jsonify({'error':'Authentication required. Please sign in.'}), 401
        # UI is rendered with a login gate; JS API calls remain protected.
        return None
    if session.get('role') == 'Viewer' and request.method not in ('GET','HEAD','OPTIONS'):
        return jsonify({'error':'Viewer role is read-only.'}), 403
    return None

@app.get('/api/auth/me')
def auth_me():
    return jsonify({'authenticated':bool(session.get('user')),'user':session.get('user'),'role':session.get('role')})


CRITICALITY = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}


def load_json(filename):
    with open(BASE / "data" / filename, encoding="utf-8") as f:
        return json.load(f)


def neo4j_status():
    return store.verify()


def get_graph_data():
    status = neo4j_status()
    if status.get("connected"):
        try:
            return store.fetch_graph(), "neo4j"
        except Exception:
            pass
    return load_json("graph.json"), "json_fallback"


def get_alerts_data():
    status = neo4j_status()
    if status.get("connected"):
        try:
            return store.fetch_alerts(), "neo4j"
        except Exception:
            pass
    return load_json("alerts.json"), "json_fallback"


def build_graph():
    data, backend = get_graph_data()
    graph = nx.MultiDiGraph()
    for node in data["nodes"]:
        graph.add_node(node["id"], **node)
    for index, edge in enumerate(data["edges"]):
        edge_id = edge.get("id") or f'{edge["source"]}|{edge["target"]}|{edge["relation"]}|{index}'
        graph.add_edge(
            edge["source"],
            edge["target"],
            key=edge_id,
            relation=edge["relation"],
            label=edge["relation"],
        )
    return graph, data, backend


def node_payload(node_id, attrs):
    return {
        "id": node_id,
        "label": attrs.get("label", node_id),
        "type": attrs.get("type", "asset"),
        "criticality": attrs.get("criticality", "medium"),
        "description": attrs.get("description", ""),
    }


def json_error(message, status=400):
    return jsonify({"error": message}), status


@app.route("/")
def home():
    return render_template("index.html")


@app.get("/api/neo4j/status")
def neo4j_status_api():
    status = neo4j_status()
    status["active_backend"] = "neo4j" if status.get("connected") else "json_fallback"
    return jsonify(status)


@app.post("/api/neo4j/import")
def neo4j_import():
    if not store.configured:
        return json_error("Neo4j is not configured. Add credentials to .env first.", 503)
    try:
        counts = store.import_dataset(load_json("graph.json"), load_json("alerts.json"))
        return jsonify({
            "ok": True,
            "counts": counts,
            "message": "Synthetic graph and alerts imported into Neo4j.",
        })
    except Exception as exc:
        return json_error(f"Neo4j import failed: {type(exc).__name__}: {exc}", 500)


@app.get("/api/graph")
def graph_data():
    data, backend = get_graph_data()
    return jsonify({"nodes": data["nodes"], "edges": data["edges"], "backend": backend})


@app.get("/api/alerts")
def alerts():
    data, backend = get_alerts_data()
    return jsonify({"alerts": data, "backend": backend})


@app.get("/api/blast-radius/<node_id>")
def blast_radius(node_id):
    graph, _, backend = build_graph()
    if node_id not in graph:
        return json_error(f"Unknown node: {node_id}", 404)
    undirected = graph.to_undirected()
    distances = nx.single_source_shortest_path_length(undirected, node_id, cutoff=3)
    impacted = [
        {**node_payload(n, graph.nodes[n]), "hops": hops}
        for n, hops in distances.items()
        if n != node_id
    ]
    impacted.sort(
        key=lambda item: (
            item["hops"],
            -CRITICALITY.get(item["criticality"], 0),
            item["label"],
        )
    )
    return jsonify(
        {
            "source": node_payload(node_id, graph.nodes[node_id]),
            "impacted": impacted,
            "counts": {
                "one_hop": sum(x["hops"] == 1 for x in impacted),
                "two_hop": sum(x["hops"] == 2 for x in impacted),
                "three_hop": sum(x["hops"] == 3 for x in impacted),
            },
            "backend": backend,
            "note": "Potential graph reachability only. This does not prove compromise or exploitability.",
        }
    )


@app.get("/api/attack-path")
def attack_path():
    graph, _, backend = build_graph()
    source = request.args.get("source", "")
    target = request.args.get("target", "")
    if source not in graph or target not in graph:
        return json_error("Choose valid source and target nodes.")
    try:
        path = nx.shortest_path(graph, source, target)
    except nx.NetworkXNoPath:
        return jsonify({"path": [], "message": "No path found in the current sample graph."})
    return jsonify(
        {
            "path": [node_payload(n, graph.nodes[n]) for n in path],
            "length": len(path) - 1,
            "backend": backend,
            "note": "Directed relationship path in the model. Not a confirmed attacker route or proof of exploitation.",
        }
    )


@app.get("/api/choke-points")
def choke_points():
    graph, _, backend = build_graph()
    centrality = nx.betweenness_centrality(graph.to_undirected(), normalized=True)
    ranked = sorted(centrality.items(), key=lambda pair: pair[1], reverse=True)
    return jsonify(
        {
            "items": [
                {**node_payload(n, graph.nodes[n]), "score": round(score, 4)}
                for n, score in ranked[:8]
                if score > 0
            ],
            "backend": backend,
            "note": "Betweenness centrality is a structural indicator. It is not a security-risk score by itself.",
        }
    )


@app.get("/api/analyst/next-step")
def analyst_next_step():
    graph, _, backend = build_graph()
    centrality = nx.betweenness_centrality(graph.to_undirected(), normalized=True)
    max_c = max(centrality.values(), default=0) or 1
    alerts_data, _ = get_alerts_data()
    alert_counts = defaultdict(int)
    for alert in alerts_data:
        for entity in alert.get("entities", []):
            alert_counts[entity] += 1
    max_a = max(alert_counts.values(), default=0) or 1

    rows = []
    for node_id, attrs in graph.nodes(data=True):
        c = centrality.get(node_id, 0) / max_c
        a = alert_counts[node_id] / max_a
        k = CRITICALITY.get(str(attrs.get("criticality", "medium")).lower(), 0.5)
        score = 0.35 * c + 0.40 * a + 0.25 * k
        reasons = []
        if c >= 0.4:
            reasons.append("lies on many shortest paths (structurally central)")
        if alert_counts[node_id]:
            reasons.append(f"referenced by {alert_counts[node_id]} alert(s)")
        if k >= 0.75:
            reasons.append(f"{attrs.get('criticality')} criticality asset")
        rows.append(
            {
                "node": node_payload(node_id, attrs),
                "score": round(score, 4),
                "alert_count": alert_counts[node_id],
                "reasons": reasons or ["lower priority based on current signals"],
            }
        )
    rows.sort(key=lambda r: r["score"], reverse=True)
    top = rows[0] if rows else None
    return jsonify(
        {
            "recommendation": top,
            "alternatives": rows[1:4],
            "backend": backend,
            "explanation": "Score combines structural centrality, alert activity, and asset criticality.",
        }
    )


@app.get("/api/copilot/explain")
def copilot_explain():
    graph, data, backend = build_graph()
    alerts_data, _ = get_alerts_data()
    high_alerts = [a for a in alerts_data if a.get("severity") in ("high", "critical")]
    critical_nodes = [n for n in data["nodes"] if n.get("criticality") == "critical"]
    return jsonify(
        {
            "summary": "Synthetic incident involving a phishing foothold that has potential paths toward privileged systems and the Payroll Database.",
            "key_observations": [
                f"{len(high_alerts)} high or critical alerts reference entities in the graph.",
                f"{len(critical_nodes)} critical assets exist in the environment model.",
                "Laptop-07 (D01) is the earliest foothold referenced by multiple alerts.",
                "Shortest paths exist from the foothold toward the Payroll Database and privileged accounts.",
            ],
            "suggested_actions": [
                "Review blast radius from Laptop-07 to understand reachable assets.",
                "Trace the shortest path from D01 to DB01 (Payroll Database).",
                "Inspect Admin Workstation and Admin Account activity.",
                "Preview isolation impact before containing any host.",
            ],
            "backend": backend,
            "caveat": "This is an evidence-backed summary of the synthetic dataset. Decision support only.",
        }
    )


@app.get("/api/isolation-preview/<node_id>")
def isolation_preview(node_id):
    graph, data, backend = build_graph()
    if node_id not in graph:
        return json_error(f"Unknown node: {node_id}", 404)
    services = [n for n in data["nodes"] if n.get("type") == "business_service"]
    affected = []
    for svc in services:
        try:
            path = nx.shortest_path(graph.to_undirected(), node_id, svc["id"])
            if len(path) <= 4:
                affected.append(
                    {"service": svc["label"], "hops": len(path) - 1, "path": path}
                )
        except nx.NetworkXNoPath:
            pass
    return jsonify(
        {
            "node": node_payload(node_id, graph.nodes[node_id]),
            "affected_services": affected,
            "backend": backend,
            "note": "Bounded dependency check. Isolating this asset may affect the listed business services.",
        }
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=os.getenv("FLASK_DEBUG", "0") == "1")
