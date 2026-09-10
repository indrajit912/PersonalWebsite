/**
 * Research Collaboration Network Graph
 * Powered by D3.js
 */

document.addEventListener("DOMContentLoaded", () => {
    const container = document.getElementById("network-container");
    if (!container) return;

    // Set dimensions
    const width = container.clientWidth;
    const height = container.clientHeight;

    // Create SVG element
    const svg = d3.select("#network-container")
        .append("svg")
        .attr("id", "network-svg")
        .attr("viewBox", [0, 0, width, height]);

    // Setup zoom/pan container
    const g = svg.append("g");
    
    const zoom = d3.zoom()
        .scaleExtent([0.2, 4])
        .on("zoom", (event) => {
            g.attr("transform", event.transform);
        });
    svg.call(zoom);

    // Setup UI Card
    const card = document.getElementById("collaborator-card");
    const nameEl = document.getElementById("collab-name");
    const websiteEl = document.getElementById("collab-website");
    const closeBtn = document.getElementById("collab-close");
    let activeNodeId = null;

    closeBtn.addEventListener("click", () => {
        card.classList.remove("show");
        activeNodeId = null;
    });

    // Fetch the data
    const dataUrl = container.getAttribute("data-source");
    
    fetch(dataUrl)
        .then(response => response.json())
        .then(rawData => {
            // Process raw data into nodes and links
            const nodes = rawData.map(d => ({ ...d }));
            const links = [];
            const edgeSet = new Set(); // Prevent duplicates

            // Build links safely
            rawData.forEach(sourceNode => {
                const processLinks = (connectionsArray, isOngoing) => {
                    if (connectionsArray) {
                        connectionsArray.forEach(targetId => {
                            // Check if target exists
                            const targetExists = rawData.some(d => d.id === targetId);
                            if (!targetExists) return;

                            // Create unique edge string (undirected)
                            const s = sourceNode.id;
                            const t = targetId;
                            if (s === t) return; // No self loops
                            
                            const edgeKey = s < t ? `${s}-${t}` : `${t}-${s}`;
                            
                            if (!edgeSet.has(edgeKey)) {
                                edgeSet.add(edgeKey);
                                links.push({ source: s, target: t, ongoing: isOngoing });
                            }
                        });
                    }
                };

                processLinks(sourceNode.connections, false);
                processLinks(sourceNode.ongoing_connections, true);
            });

            // Colors
            const colorMe = "#ff6b6b"; // Distinct color for me
            const colorCollab = "#4ecdc4"; // Color for collaborators
            const colorHover = "#ffbe76";

            // Initialize simulation
            const simulation = d3.forceSimulation(nodes)
                .force("link", d3.forceLink(links).id(d => d.id).distance(120).strength(0.5))
                .force("charge", d3.forceManyBody().strength(-800)) // Repel nodes
                .force("center", d3.forceCenter(width / 2, height / 2).strength(0.05))
                .force("collide", d3.forceCollide().radius(d => d.id === "me" ? 60 : 40));

            // Custom force to pull "me" to center strongly
            simulation.force("meCenter", alpha => {
                const me = nodes.find(n => n.id === "me");
                if (me) {
                    me.vx += (width / 2 - me.x) * alpha * 0.1;
                    me.vy += (height / 2 - me.y) * alpha * 0.1;
                }
            });

            // Draw links
            const link = g.append("g")
                .attr("class", "links")
                .selectAll("line")
                .data(links)
                .enter().append("line")
                .attr("class", d => d.ongoing ? "link ongoing-link" : "link");

            // Draw nodes
            const node = g.append("g")
                .attr("class", "nodes")
                .selectAll("g")
                .data(nodes)
                .enter().append("g")
                .attr("class", "node")
                .call(d3.drag()
                    .on("start", dragstarted)
                    .on("drag", dragged)
                    .on("end", dragended));

            // Circles
            node.append("circle")
                .attr("r", d => d.id === "me" ? 25 : 15)
                .attr("fill", d => d.id === "me" ? colorMe : colorCollab)
                .on("click", (event, d) => {
                    event.stopPropagation(); // prevent svg click
                    showCard(d, event);
                })
                .on("mouseover", function(event, d) {
                    if (activeNodeId !== d.id) {
                        d3.select(this).attr("fill", colorHover);
                    }
                })
                .on("mouseout", function(event, d) {
                    if (activeNodeId !== d.id) {
                        d3.select(this).attr("fill", d.id === "me" ? colorMe : colorCollab);
                    }
                });

            // Labels
            node.append("text")
                .attr("dx", d => d.id === "me" ? 30 : 20)
                .attr("dy", 5)
                .text(d => d.name);

            // Simulation tick updates
            simulation.on("tick", () => {
                link
                    .attr("x1", d => d.source.x)
                    .attr("y1", d => d.source.y)
                    .attr("x2", d => d.target.x)
                    .attr("y2", d => d.target.y);

                node
                    .attr("transform", d => `translate(${d.x},${d.y})`);
            });

            // Handle SVG click to hide card
            svg.on("click", () => {
                card.classList.remove("show");
                resetNodeColors();
                activeNodeId = null;
            });

            // Drag functions
            function dragstarted(event, d) {
                if (!event.active) simulation.alphaTarget(0.3).restart();
                d.fx = d.x;
                d.fy = d.y;
            }
            function dragged(event, d) {
                d.fx = event.x;
                d.fy = event.y;
            }
            function dragended(event, d) {
                if (!event.active) simulation.alphaTarget(0);
                d.fx = null;
                d.fy = null;
            }

            // UI helper
            function resetNodeColors() {
                node.selectAll("circle")
                    .attr("fill", d => d.id === "me" ? colorMe : colorCollab);
            }

            function showCard(d, event) {
                activeNodeId = d.id;
                resetNodeColors();
                
                // highlight selected
                node.selectAll("circle")
                    .filter(n => n.id === d.id)
                    .attr("fill", colorHover);

                nameEl.innerText = d.name;
                
                if (d.website && d.website.trim() !== "") {
                    websiteEl.style.display = "inline-flex";
                    websiteEl.href = d.website;
                } else {
                    websiteEl.style.display = "none";
                }

                // Show temporarily to measure dimensions if needed
                card.classList.add("show");
                
                // Get node's screen position
                const nodeRect = event.target.getBoundingClientRect();
                const containerRect = container.getBoundingClientRect();
                const cardRect = card.getBoundingClientRect();
                
                // Position horizontally centered above the node
                let x = (nodeRect.left - containerRect.left) + (nodeRect.width / 2) - (cardRect.width / 2);
                let y = (nodeRect.top - containerRect.top) - cardRect.height - 15;
                
                // Keep within container bounds horizontally
                if (x < 10) x = 10;
                if (x + cardRect.width + 10 > containerRect.width) {
                    x = containerRect.width - cardRect.width - 10;
                }
                
                // If it goes off the top edge, place it below the node instead
                if (y < 10) {
                    y = (nodeRect.bottom - containerRect.top) + 15;
                }

                card.style.left = x + "px";
                card.style.top = y + "px";
            }
        })
        .catch(err => console.error("Error loading network data:", err));
});
