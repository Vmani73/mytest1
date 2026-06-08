-----

## name: business-logic-analyzer
description: Systematic analysis of monolith repository to extract all business logic, domain context, upstream/downstream dependencies, and component relationships BEFORE migration decisions are made. No assumptions. Fact-based discovery only.
license: Complete terms in LICENSE.txt

# Business Logic Analyzer Skill

**Problem:** Migration decisions are made blind. Teams don’t know what they’re breaking until something breaks.

**Solution:** Comprehensive, unbiased discovery of business logic, domain boundaries, dependencies, and integrations BEFORE extraction begins.

-----

## When to Use This Skill

**Prerequisite to:** Monolith-to-microservices migration, domain mapping, bounded context identification, service extraction planning.

**Triggers:**

- “Analyze the business logic of this monolith”
- “Map all domains, upstream/downstream services, and data ownership”
- “Generate a complete business domain analysis document”
- “What does this application actually do? Who depends on it?”
- “Before we migrate this, I need to understand what could break”

**Output:** A complete `/migration/` folder with 8 discovery documents + analysis script.

-----

## Discovery Methodology

### Phase 1: Code-Level Analysis (What The System Does)

Use AST parsing + pattern matching to extract business logic WITHOUT reading all code:

```bash
# Find business logic entry points
- HTTP controllers (@RestController, @Controller)
- Service classes (@Service, *Service.java)
- Message listeners (Kafka, JMS, RabbitMQ)
- Scheduled tasks (@Scheduled, Quartz)
- CLI commands (Spring Shell, Picocli)
- Batch jobs (Spring Batch, custom)

# Extract high-level operations from each entry point
- Method signatures
- @RequestMapping paths and HTTP methods
- @KafkaListener topics
- @Scheduled expressions
- Parameter types (what data flows in)
- Return types (what data flows out)
```

Output: `business-logic-overview.md` with:

- All entry points categorized by type (HTTP, async, scheduled, batch)
- High-level business operations (no implementation details)
- Data flow (inputs → outputs)
- No assumptions about WHY, just WHAT

### Phase 2: Data Ownership Analysis (What Data Does It Own)

```bash
# Persistence layer discovery
- Find all JPA Entities, Mongo documents, SQL tables
- For EACH entity:
  - Table name
  - Primary key strategy
  - Relationships (1:1, 1:N, M:N)
  - Data access patterns (read/write frequency hints)
  - Audit columns (created_by, updated_at → ownership)
  - Foreign keys (indicates dependencies on other domains)

# Database schema analysis (if accessible)
- Table ownership (schema prefixes suggest domain)
- Example: "loan_*", "account_*", "payment_*" = separate domains
- Constraints indicate cross-domain dependencies

# Flyway/Liquibase migrations
- Migration chronology reveals data evolution
- Comments in migrations reveal business intent
```

Output: `data-ownership.md` with:

- All entities/tables owned by this module
- Relationships to other domains’ data
- Access patterns (read-heavy? write-heavy?)
- Audit trail information
- Data sensitivity classification (if marked in code)

### Phase 3: Dependency Mapping (What It Depends On)

```bash
# Direct dependencies
- Scan build.gradle/pom.xml for:
  - Direct library imports
  - Framework versions (Spring Boot version → capabilities)
  - Third-party integrations (Kafka, databases, caches)
  - Deprecated vs current libraries (risk indicators)

# Code-level dependencies
- Spring @Bean, @Autowired, @Inject → components this system needs
- RestTemplate, WebClient → HTTP clients to external services
- @FeignClient → declared upstream service dependencies
- JdbcTemplate, MongoTemplate → data access libraries

# Runtime dependencies
- Database connections (URL, credentials location)
- Message brokers (Kafka, RabbitMQ topics)
- External APIs (REST endpoints, SOAP services)
- Cache backends (Redis, Memcached)
- Authentication/authorization systems (OAuth, LDAP)
```

Output: `dependencies.md` with:

- All third-party libraries (category + version)
- Framework capabilities (caching, transactions, security)
- External system connections (host, port, credentials location)
- Risk assessment (deprecated libraries, version gaps)

### Phase 4: Upstream Services (Who Calls This System)

```bash
# Public API surface
- Find all @RestController methods with @GetMapping, @PostMapping, etc.
- For each endpoint:
  - Path pattern
  - HTTP method
  - Content-type (JSON, XML, form-encoded)
  - Authentication required?
  - Rate limiting?

# Message consumption
- Kafka topics consumed
- JMS queues/topics listened to
- RabbitMQ exchanges subscribed

# Other entry points
- gRPC services
- SOAP endpoints
- GraphQL queries (if applicable)

# Extract from documentation
- OpenAPI/Swagger specs
- README.md
- docs/ folder
- API gateway configs (if accessible)
```

Output: `upstream-services.md` with:

- All exposed APIs (paths, methods, content-types)
- Message topics consumed
- Authentication requirements
- SLA/rate limiting expectations
- Known upstream consumers (from git blame, comments, monitoring)

### Phase 5: Downstream Services (What This System Calls)

```bash
# Outbound HTTP calls
- RestTemplate, WebClient usage
- HTTP URLs detected in code
- @FeignClient interfaces (external services)
- URL construction patterns (suggest multiple endpoints)

# Message production
- @KafkaTemplate usage → topics produced
- JmsTemplate usage → queues/topics
- RabbitTemplate usage → exchanges

# Database calls to other domains
- Check if reads/writes to non-owned tables
- Foreign key usage
- Cross-schema queries

# Cache usage
- Redis, Memcached endpoints
- Cache key patterns suggest data accessed

# File system / blob storage
- S3, GCS, Azure Blob connections
- NFS/SMB mounts
- Local file writes

# Search engines
- Elasticsearch, Solr connections
- Index names suggest data dependencies

# Third-party APIs
- Payment gateways, shipping APIs, etc.
```

Output: `downstream-services.md` with:

- All HTTP endpoints called (host, path, method)
- Kafka/JMS topics produced
- Database systems accessed
- Cache systems used
- File/blob storage systems
- Criticality of each dependency (fail-stop vs optional)

### Phase 6: Domain Boundary Analysis (What Are The Natural Seams)

```bash
# Package structure analysis
- Check if code is organized by domain or by layer
- Example: /com/wells-fargo/lending/* vs /com/wells-fargo/service/*
- Domain organization = clearer boundaries
- Layer organization = requires deeper analysis

# Data model structure
- Which entities are accessed together?
- Which entities are independent?
- Use: co-access patterns from repositories

# Transaction boundaries
- @Transactional scope (method? class? method group?)
- If one transaction spans multiple domains = tight coupling
- Multiple small transactions = loose coupling

# Event/message structure
- Do events contain data from multiple domains?
- Or domain-isolated events?

# Code cross-references
- Which packages import from which packages most?
- Build a cross-package import frequency matrix
```

Output: `domain-map.md` with:

- Natural domain clusters (identified by structure, not assumed)
- Data cohesion within each domain
- Cross-domain dependencies (explicit)
- Transaction scope observations
- Candidate bounded contexts (with confidence score)
- Areas of tight coupling (risks)

### Phase 7: Integration Points (What Could Break)

```bash
# API contracts
- Request/response schemas
- Query parameters and their meaning
- Headers required (auth, correlation ID, etc.)
- Error responses (success/failure criteria)

# Data transformations
- Input validation rules
- Serialization/deserialization (date formats, number formats)
- Character encoding assumptions
- NULL handling

# State management
- Session state? Distributed or local?
- Cache invalidation strategies
- Eventual consistency windows

# Failure modes
- Timeouts (where are they set?)
- Retries (exponential backoff? circuit breaker?)
- Fallbacks (graceful degradation?)

# Asynchronous patterns
- Message ordering requirements?
- Exactly-once vs at-least-once semantics?
- Dead letter queue handling?
- Idempotency keys?

# Consistency requirements
- ACID transactions or BASE?
- Cross-service transactions (sagas?)
- Data synchronization mechanisms
```

Output: `integrations.md` with:

- All integration points (HTTP, async, DB, file, cache)
- Contract specifications (request/response schema)
- Failure handling strategies
- Consistency guarantees
- Breaking changes risk assessment

### Phase 8: Architecture Decisions (Why Is It Built This Way?)

```bash
# Mining decision rationale
- Git commit messages (look for "because", "to avoid", "fix for")
- Code comments with explanations
- TODO/FIXME comments (reveal known limitations)
- Deprecated code (reveals evolution)
- ADR documents (if they exist)
- CHANGELOG entries

# Constraints and trade-offs
- Performance constraints (if optimizations exist)
- Scalability decisions (sharding, partitioning)
- Security decisions (encryption, hashing)
- Compliance requirements (if evident in code)

# Known issues
- Commented-out code
- Known bugs (in comments)
- Tech debt acknowledged
- Performance bottlenecks identified
```

Output: `architecture-decisions.md` with:

- Key architectural choices (and reasons when discoverable)
- Known limitations
- Technical debt
- Scaling constraints
- Compliance/regulatory considerations
- Evolution history

### Phase 9: Risk Assessment (What Could Break During Migration)

```bash
# Identify fragile areas
- Tight coupling indicators:
  - Shared mutable state
  - Distributed transactions
  - Implicit assumptions (e.g., execution order)
  
- Behavioral coupling:
  - Race conditions
  - Event ordering assumptions
  - Cache coherency assumptions

- Data consistency risks:
  - Cross-service queries
  - Foreign key constraints across schemas
  - Eventual consistency windows

- Performance risks:
  - N+1 queries
  - Full table scans
  - Synchronous call chains

- Observability gaps:
  - Missing traces
  - Insufficient logging
  - No metrics for critical paths
```

Output: `risk-factors.md` with:

- High-risk coupling points
- Data consistency risks
- Performance concerns
- Observability gaps
- Fallback strategies needed
- Pre-migration infrastructure requirements

-----

## Implementation: Discovery Script

Create `migration/analyze-business-logic.py`:

```python
#!/usr/bin/env python3
"""
Comprehensive business logic analyzer.
Produces 8 markdown files in /migration/ folder.
No assumptions. Fact-based discovery only.
"""

import os
import json
import re
from pathlib import Path
from collections import defaultdict
import subprocess

class BusinessLogicAnalyzer:
    def __init__(self, repo_root):
        self.repo_root = Path(repo_root)
        self.findings = defaultdict(list)
        
    def analyze_all(self):
        """Run complete discovery"""
        print("[1/9] Scanning codebase structure...")
        self.scan_source_structure()
        
        print("[2/9] Extracting entry points...")
        self.extract_entry_points()
        
        print("[3/9] Mapping data ownership...")
        self.map_data_ownership()
        
        print("[4/9] Analyzing dependencies...")
        self.analyze_dependencies()
        
        print("[5/9] Identifying upstream services...")
        self.identify_upstream()
        
        print("[6/9] Identifying downstream services...")
        self.identify_downstream()
        
        print("[7/9] Discovering domain boundaries...")
        self.discover_domain_boundaries()
        
        print("[8/9] Mapping integrations...")
        self.map_integrations()
        
        print("[9/9] Assessing risks...")
        self.assess_risks()
        
        print("\n[Writing] Business logic overview...")
        self.write_business_logic_overview()
        
        print("[Writing] Data ownership...")
        self.write_data_ownership()
        
        print("[Writing] Dependencies...")
        self.write_dependencies()
        
        print("[Writing] Upstream services...")
        self.write_upstream()
        
        print("[Writing] Downstream services...")
        self.write_downstream()
        
        print("[Writing] Domain map...")
        self.write_domain_map()
        
        print("[Writing] Integrations...")
        self.write_integrations()
        
        print("[Writing] Architecture decisions...")
        self.write_arch_decisions()
        
        print("[Writing] Risk assessment...")
        self.write_risk_assessment()
        
        print("\n✅ Analysis complete. See /migration/ folder.")
        
    def scan_source_structure(self):
        """Scan Java source tree"""
        # Find all .java files
        # Categorize: controllers, services, repos, entities, utils
        # Build package hierarchy
        pass
    
    def extract_entry_points(self):
        """Find @RestController, @Service, @Kafka, @Scheduled, etc."""
        # Use grep/regex to find:
        # - @RestController classes + methods
        # - @Service classes
        # - @KafkaListener methods
        # - @Scheduled methods
        # - Spring Batch jobs
        # - CLI commands
        pass
    
    def map_data_ownership(self):
        """Find JPA Entities, repositories, database tables"""
        # @Entity annotations
        # @Table names
        # Repository interfaces
        # Flyway migrations
        pass
    
    def analyze_dependencies(self):
        """Parse build.gradle/pom.xml"""
        # Extract dependencies
        # Check for deprecated libraries
        # Version analysis
        pass
    
    def identify_upstream(self):
        """Extract all exposed APIs"""
        # @RequestMapping patterns
        # @KafkaListener topics
        # @MessageListener
        # gRPC, SOAP, GraphQL endpoints
        pass
    
    def identify_downstream(self):
        """Find outbound calls"""
        # RestTemplate, WebClient usage
        # @FeignClient declarations
        # Database connections to external schemas
        # Kafka topics produced
        # HTTP URLs in code
        pass
    
    def discover_domain_boundaries(self):
        """Analyze natural domain seams"""
        # Package structure
        # Data model cohesion
        # Transaction scope
        # Cross-package dependencies
        pass
    
    def map_integrations(self):
        """Document all integration points"""
        # HTTP contracts
        # Message schemas
        # Data transformation rules
        # Failure handling
        pass
    
    def assess_risks(self):
        """Identify fragile areas"""
        # Tight coupling indicators
        # Distributed transactions
        # Consistency risks
        # Performance concerns
        # Observability gaps
        pass
    
    def write_business_logic_overview(self):
        """Generate business-logic-overview.md"""
        # High-level summary
        # All entry points
        # Data flows
        pass
    
    def write_data_ownership(self):
        """Generate data-ownership.md"""
        # All entities/tables
        # Relationships
        # Foreign key dependencies
        pass
    
    def write_dependencies(self):
        """Generate dependencies.md"""
        # Third-party libraries
        # Framework capabilities
        # External systems
        pass
    
    def write_upstream(self):
        """Generate upstream-services.md"""
        # Exposed APIs
        # Auth requirements
        # SLAs
        pass
    
    def write_downstream(self):
        """Generate downstream-services.md"""
        # Called services
        # Criticality
        # Failure impact
        pass
    
    def write_domain_map(self):
        """Generate domain-map.md"""
        # Domain clusters
        # Cross-domain deps
        # Coupling metrics
        pass
    
    def write_integrations(self):
        """Generate integrations.md"""
        # All integration points
        # Contracts
        # Breaking changes risks
        pass
    
    def write_arch_decisions(self):
        """Generate architecture-decisions.md"""
        # Key decisions
        # Known limitations
        # Tech debt
        pass
    
    def write_risk_assessment(self):
        """Generate risk-factors.md"""
        # Fragile areas
        # Data consistency risks
        # Pre-migration requirements
        pass

if __name__ == '__main__':
    import sys
    repo = sys.argv[1] if len(sys.argv) > 1 else '.'
    analyzer = BusinessLogicAnalyzer(repo)
    analyzer.analyze_all()
```

-----

## Output Files

Each file is standalone, fact-based, with evidence chains:

### business-logic-overview.md

```markdown
# Business Logic Overview

**Generated:** [timestamp]
**Repository:** [repo]
**Scope:** Complete entry point and operation mapping

## Entry Points

### HTTP Controllers (REST API)
[Automatically extracted table of paths, methods, auth requirements]

### Message Consumers
[Kafka topics, JMS queues, processing logic]

### Scheduled Tasks
[Cron expressions, frequency, purpose]

### Batch Jobs
[Job names, triggers, data volume]

## Data Flows
[Input → Processing → Output for each operation]

## No Assumptions
[List any gaps or ambiguities that need clarification]
```

### upstream-services.md

```markdown
# Upstream Services (Who Calls This System)

[Table with columns:]
- Endpoint / Topic
- HTTP Method or Message Type
- Authentication
- Known Consumers
- Frequency
- SLA/Timeout
- Breaking Changes Since Last Version

[Evidence: grep results, swagger specs, git blame]
```

### downstream-services.md

```markdown
# Downstream Services (What This System Calls)

[Table with columns:]
- Service / System
- Type (HTTP, Kafka, DB, Cache, etc.)
- Criticality (fail-stop or optional)
- Failure Mode
- Retry Strategy
- Circuit Breaker Status

[Evidence: RestTemplate usage, Kafka configs, datasource URLs]
```

### data-ownership.md

```markdown
# Data Ownership

[Table with columns:]
- Entity / Table
- Primary Domain
- Owned By (this module or external)
- Relationships (to other entities)
- Access Pattern (RW frequency)
- Audit Trail

[Evidence: @Entity annotations, schema analysis, migration history]
```

### domain-map.md

```markdown
# Domain Map & Bounded Contexts

[Visual: ASCII diagram of domains and relationships]

## Identified Domains
[List with confidence score and evidence]

## Cross-Domain Dependencies
[Matrix: domain A calls domain B]

## Data Cohesion Analysis
[Entities that are accessed together = cohesive]

## Transaction Scope Observations
[Multi-domain transactions = coupling risk]
```

### risk-factors.md

```markdown
# Risk Assessment for Migration

## High-Risk Coupling Points
[List specific code locations and why they're risky]

## Data Consistency Risks
[Cross-service queries, distributed transactions]

## Pre-Migration Infrastructure Required
[APM, circuit breakers, sagas framework, etc.]

## Observability Gaps
[Missing traces, insufficient logging, no metrics]
```

-----

## How to Use in Migration Process

1. **Before Phase 1**: Run this analyzer
1. **During Phase 1 (Inventory)**: Use analysis output to cross-check
1. **During Phase 2 (Domain Analysis)**: Ratify domains against discovered boundaries
1. **During Phase 3+ (Extraction)**: Reference risk factors to guide hardening

-----

## Key Principle: No Assumptions

This skill:

- ❌ Does NOT guess at business logic
- ❌ Does NOT assume domain boundaries without evidence
- ❌ Does NOT create “obvious” dependencies not in code
- ✅ Documents ONLY what can be discovered
- ✅ Marks ambiguities explicitly
- ✅ Provides evidence for every claim
- ✅ Recommends clarification from domain experts

-----

## Success Criteria

After running this skill, you should be able to:

- [ ] List every exposed API endpoint
- [ ] Identify all upstream consumers (from code evidence)
- [ ] Map all downstream dependencies
- [ ] Understand which data this system owns vs borrows
- [ ] Identify natural domain seams
- [ ] Spot high-risk coupling points
- [ ] Make informed extraction decisions
- [ ] Explain to leadership what could break