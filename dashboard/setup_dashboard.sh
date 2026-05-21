Dashboard structure:
dashboard
├── app.py
├── auth
│   └── init.py
├── charts
│   ├── heatmaps.py
│   ├── mitre_graph.py
│   ├── risk_charts.py
│   └── timelines.py
├── components
│   ├── findings.py
│   ├── metric_cards.py
│   ├── scheduler.py
│   └── sidebar.py
├── Dockerfile
├── pages
│   ├── analytics.py
│   ├── campaigns.py
│   ├── infrastructure.py
│   ├── launch.py
│   ├── mitre.py
│   ├── realtime.py
│   ├── reports.py
│   └── soc_validation.py
├── realtime
│   ├── event_stream.py
│   └── telemetry.py
├── reports
│   ├── executive_summary.py
│   └── pdf_generator.py
├── requirements.txt
├── services
│   ├── api_client.py
│   ├── campaign_engine.py
│   ├── elk_service.py
│   ├── replay_engine.py
│   └── websocket_client.py
└── utils
    └── init.py

9 directories, 30 files
kushagra@ZEROBOOK:~/secureforge$ ^C