import dash
from dash import dcc, html, Input, Output
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from data_loader import load_sessions

# Загрузка данных
df, sessions = load_sessions('Logs/sessions.json')

# Агрегация по сессиям
df_sessions = df.groupby('session_id').agg({
    'type': 'first',
    'ip': 'first',
    'username': 'first',
    'tactics': 'first',
    'num_tactics': 'first',
    'num_commands': 'first',
    'has_C2': 'first',
    'has_PrivEsc': 'first',
    'has_Discovery': 'first',
    'has_Execution': 'first',
    'has_Impact': 'first',
}).reset_index()

# Тактики по сессиям
tactic_counts = pd.DataFrame({
    'Tactic': ['Collection', 'Command and Control', 'Credential Access',
               'Defense Evasion', 'Discovery', 'Execution', 'Exfiltration',
               'Impact', 'Initial Access', 'Lateral Movement',
               'Persistence', 'Privilege Escalation', 'Unknown'],
    'Count': [
        df_sessions['has_Discovery'].sum() if t == 'Discovery' else
        df_sessions['has_C2'].sum() if t == 'Command and Control' else
        df_sessions['has_PrivEsc'].sum() if t == 'Privilege Escalation' else
        df_sessions['has_Execution'].sum() if t == 'Execution' else
        df_sessions['has_Impact'].sum() if t == 'Impact' else
        0
        for t in ['Collection', 'Command and Control', 'Credential Access',
                  'Defense Evasion', 'Discovery', 'Execution', 'Exfiltration',
                  'Impact', 'Initial Access', 'Lateral Movement',
                  'Persistence', 'Privilege Escalation', 'Unknown']
    ]
})

# Dash приложение
app = dash.Dash(__name__, title='Анализ датасета SSH-сессий')

app.layout = html.Div([
    html.H1('Анализ датасета SSH-сессий', style={'textAlign': 'center'}),

    # Метрики
    html.Div([
        html.Div([
            html.H3(f'{len(df_sessions)}'),
            html.P('Всего сессий')
        ], className='metric-card'),
        html.Div([
            html.H3(f'{len(df_sessions[df_sessions["type"] == "benign"])}'),
            html.P('Benign')
        ], className='metric-card'),
        html.Div([
            html.H3(f'{len(df_sessions[df_sessions["type"] == "malicious"])}'),
            html.P('Malicious')
        ], className='metric-card'),
        html.Div([
            html.H3(f'{len(df_sessions[df_sessions["type"] == "mixed"])}'),
            html.P('Mixed')
        ], className='metric-card'),
    ], style={'display': 'flex', 'justifyContent': 'space-around', 'margin': '20px'}),

    # Графики
    html.Div([
        # Pie chart: типы сессий
        html.Div([
            dcc.Graph(
                figure=px.pie(
                    df_sessions,
                    names='type',
                    title='Распределение типов сессий',
                    color='type',
                    color_discrete_map={'benign': '#2ecc71', 'malicious': '#e74c3c', 'mixed': '#f39c12'}
                )
            )
        ], style={'width': '33%', 'display': 'inline-block'}),

        # Bar chart: тактики
        html.Div([
            dcc.Graph(
                figure=px.bar(
                    tactic_counts,
                    x='Tactic',
                    y='Count',
                    title='Частота тактик MITRE',
                    color='Tactic'
                )
            )
        ], style={'width': '33%', 'display': 'inline-block'}),

        # Histogram: длины сессий
        html.Div([
            dcc.Graph(
                figure=px.histogram(
                    df_sessions,
                    x='num_commands',
                    color='type',
                    title='Распределение длины сессий',
                    nbins=30,
                    color_discrete_map={'benign': '#2ecc71', 'malicious': '#e74c3c', 'mixed': '#f39c12'}
                )
            )
        ], style={'width': '33%', 'display': 'inline-block'}),
    ]),

    # Вторая строка графиков
    html.Div([
        # Top-20 команд
        html.Div([
            dcc.Graph(
                figure=px.bar(
                    df['cmd'].value_counts().head(20).reset_index(),
                    x='count',
                    y='cmd',
                    title='Топ-20 команд',
                    orientation='h'
                )
            )
        ], style={'width': '50%', 'display': 'inline-block'}),

        # Heatmap: корреляция тактик
        html.Div([
            dcc.Graph(
                figure=go.Figure(data=go.Heatmap(
                    z=df_sessions[['has_C2', 'has_PrivEsc', 'has_Discovery', 'has_Execution', 'has_Impact']].corr(),
                    x=['C2', 'PrivEsc', 'Discovery', 'Execution', 'Impact'],
                    y=['C2', 'PrivEsc', 'Discovery', 'Execution', 'Impact'],
                    colorscale='RdBu',
                    zmin=-1, zmax=1
                )).update_layout(title='Корреляция тактик')
            )
        ], style={'width': '50%', 'display': 'inline-block'}),
    ]),

    # Таблица последних сессий
    html.Div([
        html.H3('Последние сессии'),
        dcc.Dropdown(
            id='type-filter',
            options=[
                {'label': 'Все', 'value': 'all'},
                {'label': 'Benign', 'value': 'benign'},
                {'label': 'Malicious', 'value': 'malicious'},
                {'label': 'Mixed', 'value': 'mixed'},
            ],
            value='all'
        ),
        html.Div(id='sessions-table')
    ])
])


@app.callback(
    Output('sessions-table', 'children'),
    Input('type-filter', 'value')
)
def update_table(selected_type):
    if selected_type == 'all':
        filtered = df_sessions
    else:
        filtered = df_sessions[df_sessions['type'] == selected_type]

    return html.Table([
        html.Thead(html.Tr([html.Th(c) for c in ['ID', 'Type', 'IP', 'Username', 'Commands', 'Tactics']])),
        html.Tbody([
            html.Tr([
                html.Td(row['session_id'][:8]),
                html.Td(row['type']),
                html.Td(row['ip']),
                html.Td(row['username']),
                html.Td(row['num_commands']),
                html.Td(row['tactics'][:50] + '...' if len(row['tactics']) > 50 else row['tactics']),
            ]) for _, row in filtered.head(20).iterrows()
        ])
    ])


if __name__ == '__main__':
    app.run(debug=True, port=8050)