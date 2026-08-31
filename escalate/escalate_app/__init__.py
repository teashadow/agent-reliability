"""escalate — multi-turn resilience prober (MAD battery).

Probes YOUR OWN LLM endpoint with a crescendo-style multi-turn session and
reports whether the target holds (rc=0), a rung performed (rc=1, finding),
or the check could not run (rc=2, not_proven).
"""
