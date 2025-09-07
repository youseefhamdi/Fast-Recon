import plotly.express as px
import pandas as pd

# Data
data = [
  {"tool": "SUBFINDER", "type": "Passive", "sources": "25+", "speed": "Very Fast", "language": "Go"},
  {"tool": "ASSETFINDER", "type": "Passive", "sources": "5+", "speed": "Fast", "language": "Go"},
  {"tool": "AMASS", "type": "Active/Passive", "sources": "55+", "speed": "Medium", "language": "Go"},
  {"tool": "BBOT", "type": "Active/Passive", "sources": "50+", "speed": "Fast", "language": "Python"},
  {"tool": "FFUF", "type": "Active", "sources": "Wordlist-based", "speed": "Very Fast", "language": "Go"},
  {"tool": "SUBDOG", "type": "Passive", "sources": "Multiple", "speed": "Fast", "language": "Go"},
  {"tool": "SUDOMY", "type": "Active/Passive", "sources": "20+", "speed": "Medium", "language": "Bash"},
  {"tool": "DNSCAN", "type": "Active", "sources": "Wordlist-based", "speed": "Fast", "language": "Python"},
  {"tool": "SUBDOMAINATOR", "type": "Passive", "sources": "50+", "speed": "Fast", "language": "Go"},
  {"tool": "ASN/CIDR", "type": "Passive", "sources": "Multiple", "speed": "Fast", "language": "Various"}
]

# Create DataFrame
df = pd.DataFrame(data)

# Count tools by speed category
speed_counts = df['speed'].value_counts()

# Create DataFrame for plotting with proper ordering
plot_df = pd.DataFrame({
    'Speed': ['Very Fast', 'Fast', 'Medium'],
    'Count': [speed_counts.get('Very Fast', 0), speed_counts.get('Fast', 0), speed_counts.get('Medium', 0)]
})

# Define colors from the brand palette
colors = ['#1FB8CD', '#DB4545', '#2E8B57']

# Create horizontal bar chart
fig = px.bar(plot_df, 
             x='Count', 
             y='Speed', 
             orientation='h',
             color='Speed',
             color_discrete_sequence=colors,
             title='Tool Speed Performance')

# Update layout and styling
fig.update_traces(cliponaxis=False)
fig.update_layout(
    xaxis_title='Tool Count',
    yaxis_title='Speed Category',
    showlegend=False
)

# Save the chart
fig.write_image('speed_performance_chart.png')