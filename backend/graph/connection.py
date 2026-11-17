"""One shared Neo4j driver for the whole app."""
import certifi
from neo4j import GraphDatabase, TrustCustomCAs

import config

uri = config.NEO4J_URI
tls_options = {}
if "+s://" in uri:
    uri = uri.replace("+s://", "://", 1)
    tls_options = {
        "encrypted": True,
        "trusted_certificates": TrustCustomCAs(certifi.where()),
    }

driver = GraphDatabase.driver(
    uri,
    auth=(config.NEO4J_USER, config.NEO4J_PASSWORD),
    **tls_options,
)


def run(query, **params):
    """Run a read query and return the rows as plain dicts."""
    records, _, _ = driver.execute_query(query, params, routing_="r")
    return [r.data() for r in records]


def write(query, **params):
    """Run a query that changes the database (used only by the embedding script)."""
    driver.execute_query(query, params, routing_="w")
