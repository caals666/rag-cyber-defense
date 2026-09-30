"""One shared Neo4j driver for the whole app."""
from neo4j import GraphDatabase

import config

driver = GraphDatabase.driver(config.NEO4J_URI, auth=(config.NEO4J_USER, config.NEO4J_PASSWORD))


def run(query, **params):
    """Run a read query and return the rows as plain dicts."""
    records, _, _ = driver.execute_query(query, params, routing_="r")
    return [r.data() for r in records]
