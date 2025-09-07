import plotly.express as px
import pandas as pd

# Create the data
data = [
    {"type": "Active", "count": 3, "tools": ["FFUF", "DNSCAN", "ASN/CIDR"]},
    {"type": "Passive", "count": 4, "tools": ["SUBFINDER", "ASSETFINDER", "SUBDOG", "SUBDOMAINATOR"]},
    {"type": "Active/Passive", "count": 3, "tools": ["AMASS", "BBOT", "SUDOMY"]}
]

# Create DataFrame
df = pd.DataFrame(data)

# Calculate percentages
total = df['count'].sum()
df['percentage'] = (df['count'] / total * 100).round(1)

# Create pie chart
fig = px.pie(df, 
             values='count', 
             names='type',
             title='Recon Tools by Enumeration Type',
             color_discrete_sequence=['#1FB8CD', '#DB4545', '#2E8B57'])

# Update traces for better formatting
fig.update_traces(
    textposition='inside',
    textinfo='percent+label'
)

# Update layout for pie chart specific requirements
fig.update_layout(
    uniformtext_minsize=14, 
    uniformtext_mode='hide'
)

# Save the chart
fig.write_image('recon_tools_pie_chart.png')