import plotly.graph_objects as go
import plotly.express as px
import numpy as np

# Define the architecture layers and components with proper names
architecture_data = {
    "Input": ["Target Domain", "Org Name", "IP Range", "ASN Number"],
    "MCP Recon Server": ["Subfinder", "Amass", "Assetfinder", "BBOT", "FFUF", "Subdog", "Sudomy", "Dnscan", "Subdomainator", "ASN&CIDR Tools"],
    "FastMCP Framework": ["@mcp.tool Dec", "Tool Wrappers", "Schema Gen", "Async Process"],
    "Transport Layer": ["stdio", "HTTP/SSE", "Stream HTTP", "JSON-RPC 2.0"],
    "AI Clients": ["Claude Desktop", "VS Code Ext", "Custom AI Apps", "CLI Clients"],
    "Output": ["Subdomains", "IP Ranges", "Vulnerabilities", "Asset Inventory", "JSON/CSV Rpts"]
}

# Define colors for each layer
layer_colors = {
    "Input": "#1FB8CD",
    "MCP Recon Server": "#DB4545", 
    "FastMCP Framework": "#2E8B57",
    "Transport Layer": "#5D878F",
    "AI Clients": "#D2BA4C",
    "Output": "#B4413C"
}

# Create figure
fig = go.Figure()

# Position components
y_positions = {
    "Input": 5,
    "MCP Recon Server": 4,
    "FastMCP Framework": 3,
    "Transport Layer": 2,
    "AI Clients": 1,
    "Output": 0
}

# Add components for each layer
for layer, components in architecture_data.items():
    y_pos = y_positions[layer]
    color = layer_colors[layer]
    
    # Calculate x positions with proper spacing
    num_components = len(components)
    if num_components == 1:
        x_positions = [0]
    elif num_components <= 4:
        x_positions = np.linspace(-2, 2, num_components)
    else:
        # For layers with many components, use wider spacing
        x_positions = np.linspace(-4, 4, num_components)
    
    # Add each component with rectangle and text
    for i, component in enumerate(components):
        x_pos = x_positions[i]
        
        # Determine box width based on text length
        box_width = max(0.5, len(component) * 0.06)
        
        # Add rectangular background
        fig.add_shape(
            type="rect",
            x0=x_pos-box_width/2, y0=y_pos-0.15,
            x1=x_pos+box_width/2, y1=y_pos+0.15,
            fillcolor=color,
            line=dict(color="white", width=2),
        )
        
        # Add the component text on top of rectangle
        fig.add_trace(go.Scatter(
            x=[x_pos],
            y=[y_pos],
            mode='text',
            text=component,
            textposition='middle center',
            textfont=dict(size=10, color='white', family="Arial Black"),
            showlegend=False,
            hovertemplate=f"<b>{component}</b><br>Layer: {layer}<extra></extra>"
        ))

# Add layer labels on the left with proper positioning
layer_label_mapping = {
    "Input": "Input Layer",
    "MCP Recon Server": "MCP Recon<br>Server", 
    "FastMCP Framework": "FastMCP<br>Framework",
    "Transport Layer": "Transport<br>Layer",
    "AI Clients": "AI Clients<br>Layer",
    "Output": "Output Layer"
}

for layer, y_pos in y_positions.items():
    fig.add_trace(go.Scatter(
        x=[-5.5],
        y=[y_pos],
        mode='text',
        text=f"<b>{layer_label_mapping[layer]}</b>",
        textposition='middle center',
        textfont=dict(size=12, color='#333333', family="Arial"),
        showlegend=False,
        hoverinfo='skip'
    ))

# Add flow arrows between layers
arrow_pairs = [
    ("Input", "MCP Recon Server"),
    ("MCP Recon Server", "FastMCP Framework"), 
    ("FastMCP Framework", "Transport Layer"),
    ("Transport Layer", "AI Clients"),
    ("AI Clients", "Output")
]

for from_layer, to_layer in arrow_pairs:
    from_y = y_positions[from_layer]
    to_y = y_positions[to_layer]
    
    # Main arrow line
    fig.add_shape(
        type="line",
        x0=0, y0=from_y-0.25,
        x1=0, y1=to_y+0.25,
        line=dict(color="#2E8B57", width=5),
    )
    
    # Arrowhead
    fig.add_shape(
        type="line",
        x0=-0.2, y0=to_y+0.4,
        x1=0, y1=to_y+0.25,
        line=dict(color="#2E8B57", width=5),
    )
    fig.add_shape(
        type="line",
        x0=0.2, y0=to_y+0.4,
        x1=0, y1=to_y+0.25,
        line=dict(color="#2E8B57", width=5),
    )

# Add title box at the top
fig.add_shape(
    type="rect",
    x0=-2, y0=5.7,
    x1=2, y1=6.1,
    fillcolor="#13343B",
    line=dict(color="white", width=2),
)

fig.add_trace(go.Scatter(
    x=[0],
    y=[5.9],
    mode='text',
    text="<b>MCP Bug Bounty Recon Architecture</b>",
    textposition='middle center',
    textfont=dict(size=14, color='white', family="Arial"),
    showlegend=False,
    hoverinfo='skip'
))

# Update layout
fig.update_layout(
    title="",
    xaxis=dict(
        range=[-6.5, 5],
        showgrid=False,
        showticklabels=False,
        zeroline=False
    ),
    yaxis=dict(
        range=[-0.5, 6.5],
        showgrid=False,
        showticklabels=False,
        zeroline=False
    ),
    plot_bgcolor='white',
    paper_bgcolor='white',
    showlegend=False
)

# Update traces to disable clipping
fig.update_traces(cliponaxis=False)

# Save the chart
fig.write_image("mcp_architecture_diagram.png", width=1500, height=1000, scale=2)