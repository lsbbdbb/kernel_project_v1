#!/usr/bin/env bash
# ============================================================
# verify_all_phases.sh — 逐 Phase 验证 Phase 0-5 实现质量
# 在服务器项目根目录执行:
#   source .venv/bin/activate
#   bash scripts/verify_all_phases.sh
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass=0
fail=0

check() {
    local label="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        echo -e "  ${GREEN}[PASS]${NC} $label"
        ((pass++)) || true
    else
        echo -e "  ${RED}[FAIL]${NC} $label"
        ((fail++)) || true
    fi
}

echo "============================================"
echo " Phase 0-5 全面验证"
echo " $(date)"
echo "============================================"
echo ""

# ==================================================================
# Phase 0: 龙蜥内核编译环境
# ==================================================================
echo "── Phase 0: Docker / Anolis 编译环境 ──"

check "Dockerfile exists"                            test -f Dockerfile
check "Dockerfile uses Anolis OS 23"                 grep -q "anolisos:23" Dockerfile
check "Dockerfile installs kpatch-build"             grep -q "kpatch-build" Dockerfile
check "Dockerfile installs kernel-devel"             grep -q "kernel-devel" Dockerfile
check "docker-compose.yml exists"                    test -f docker-compose.yml
check "docker-compose has agent service"             grep -q "agent:" docker-compose.yml
check "docker-compose has agent-dev service"         grep -q "agent-dev:" docker-compose.yml
check "docker-compose has agent-run service"         grep -q "agent-run:" docker-compose.yml
check "docker-compose mounts /kernel-src"            grep -q "/kernel-src" docker-compose.yml
check "docker-compose sets KERNEL_SRC"               grep -q "KERNEL_SRC" docker-compose.yml
check "docker-entrypoint.sh exists"                  test -f docker-entrypoint.sh
check "docker-entrypoint.sh is executable"           test -x docker-entrypoint.sh
check "entrypoint has test/shell/run modes"          grep -q "test\|shell\|run" docker-entrypoint.sh
check "download_kernel_src.sh exists"                test -f scripts/download_kernel_src.sh
check "download script clones cloud-kernel"          grep -q "cloud-kernel" scripts/download_kernel_src.sh
check "download script builds vmlinux"               grep -q "make.*vmlinux" scripts/download_kernel_src.sh

echo ""

# ==================================================================
# Phase 1: 修 bug + 加载 YAML
# ==================================================================
echo "── Phase 1: 修 bug + YAML 知识加载 ──"

check "kpatch_builder.py imports shutil" \
    python -c "import ast; t=open('agent/tools/kpatch_builder.py').read(); assert 'import shutil' in t or 'from shutil' in t"

check "KnowledgeLoader module exists" \
    python -c "from agent.knowledge.loader import KnowledgeLoader"

check "KnowledgeLoader loads failure patterns (9 expected)" \
    python -c "from agent.knowledge.loader import KnowledgeLoader; p=KnowledgeLoader.load_failure_patterns(); assert len(p) >= 9, f'got {len(p)}'"

check "KnowledgeLoader loads rewrite strategies (>=4 expected)" \
    python -c "from agent.knowledge.loader import KnowledgeLoader; s=KnowledgeLoader.load_rewrite_strategies(); assert len(s) >= 4, f'got {len(s)}'"

check "FailureClassifier uses KnowledgeLoader" \
    python -c "from agent.tools.failure_classifier import FailureClassifier; p=FailureClassifier.load_patterns(); assert len(p) >= 9"

check "FailureClassifier YAML patterns include apply.file_missing" \
    python -c "from agent.knowledge.loader import KnowledgeLoader; p=KnowledgeLoader.load_failure_patterns(); ids=[x.get('pattern_id','') for x in p]; assert 'apply.file_missing' in ids"

check "FailureClassifier YAML patterns include compile.implicit_decl" \
    python -c "from agent.knowledge.loader import KnowledgeLoader; p=KnowledgeLoader.load_failure_patterns(); ids=[x.get('pattern_id','') for x in p]; assert 'compile.implicit_decl' in ids"

check "FailureClassifier YAML patterns include compile.unknown_field" \
    python -c "from agent.knowledge.loader import KnowledgeLoader; p=KnowledgeLoader.load_failure_patterns(); ids=[x.get('pattern_id','') for x in p]; assert 'compile.unknown_field' in ids"

check "FailureClassifier YAML patterns include compile.undefined_symbol" \
    python -c "from agent.knowledge.loader import KnowledgeLoader; p=KnowledgeLoader.load_failure_patterns(); ids=[x.get('pattern_id','') for x in p]; assert 'compile.undefined_symbol' in ids"

check "RewriteAdvisor uses KnowledgeLoader" \
    python -c "from agent.tools.rewrite_advisor import RewriteAdvisor; s=RewriteAdvisor.load_strategies(); assert len(s) >= 4"

echo ""

# ==================================================================
# Phase 2: LLM 集成基础
# ==================================================================
echo "── Phase 2: LLM 集成基础 ──"

check "LLMConfig module exists" \
    python -c "from agent.llm.config import LLMConfig"

check "LLMClient module exists" \
    python -c "from agent.llm.client import LLMClient"

check "LLMConfig.from_env() works" \
    python -c "from agent.llm.config import LLMConfig; c=LLMConfig.from_env(); assert c.provider in ('deepseek','openai','ollama')"

check "LLMConfig supports deepseek/openai/ollama" \
    python -c "from agent.llm.config import LLMConfig, DEFAULT_BASE_URLS; assert 'deepseek' in DEFAULT_BASE_URLS"

check "LLMClient.ping() returns False without API key" \
    python -c "from agent.llm.client import LLMClient; from agent.llm.config import LLMConfig; c=LLMClient(LLMConfig(provider='deepseek',api_key=None)); assert c.ping() == False"

check "LLMClient stores init_error when unconfigured" \
    python -c "from agent.llm.client import LLMClient; from agent.llm.config import LLMConfig; c=LLMClient(LLMConfig(provider='deepseek',api_key=None)); assert c.init_error is not None or c.client is None"

check "Prompt templates module exists" \
    python -c "from agent.llm.prompts import templates"

check "diagnose_failure template exists" \
    python -c "from agent.llm.prompts.templates import diagnose_failure; m=diagnose_failure('log','{}'); assert len(m)==2"

check "plan_rewrite_strategy template exists" \
    python -c "from agent.llm.prompts.templates import plan_rewrite_strategy; m=plan_rewrite_strategy({},{},[]); assert len(m)==2"

check "generate_rewrite_diff template exists" \
    python -c "from agent.llm.prompts.templates import generate_rewrite_diff; m=generate_rewrite_diff('patch',{},{},{},{}); assert len(m)==2"

check "decide_retry template exists" \
    python -c "from agent.llm.prompts.templates import decide_retry; m=decide_retry({},{},1,5); assert len(m)==2"

check "openai>=1.0.0 in requirements.txt" \
    grep -q "openai>=" requirements.txt

echo ""

# ==================================================================
# Phase 3: 智能 Planner
# ==================================================================
echo "── Phase 3: 智能 Planner ──"

check "LLMPlanner class exists" \
    python -c "from agent.planner import LLMPlanner"

check "LLMPlanner inherits Planner" \
    python -c "from agent.planner import LLMPlanner, Planner; assert issubclass(LLMPlanner, Planner)"

check "LLMPlanner accepts llm_client" \
    python -c "from agent.planner import LLMPlanner; from agent.state import StateManager; import tempfile; s=StateManager(tempfile.mkdtemp()); p=LLMPlanner(s, llm_client=None); assert p.llm is None"

check "LLMPlanner respects no_llm flag" \
    python -c "from agent.planner import LLMPlanner; from agent.state import StateManager; import tempfile; s=StateManager(tempfile.mkdtemp()); p=LLMPlanner(s, llm_client=None, no_llm=True); assert p.no_llm == True"

check "CLI has --no-llm argument" \
    grep -q "\-\-no-llm" agent/__main__.py

check "CLI has --llm-provider argument" \
    grep -q "\-\-llm-provider" agent/__main__.py

check "CLI has --llm-model argument" \
    grep -q "\-\-llm-model" agent/__main__.py

check "main() initializes LLMClient conditionally" \
    grep -q "LLMClient\|llm_client" agent/__main__.py

echo ""

# ==================================================================
# Phase 4: 真正的补丁改写
# ==================================================================
echo "── Phase 4: LLM 驱动的补丁改写 ──"

check "RewriteAdvisor.__init__ accepts llm_client" \
    python -c "from agent.tools.rewrite_advisor import RewriteAdvisor; import tempfile; r=RewriteAdvisor(tempfile.mkdtemp(),'CVE-X',llm_client=None); assert r.llm is None"

check "RewriteAdvisor.__init__ accepts retriever" \
    python -c "from agent.tools.rewrite_advisor import RewriteAdvisor; import tempfile; r=RewriteAdvisor(tempfile.mkdtemp(),'CVE-X',retriever=None); assert r.retriever is None"

check "_llm_rewrite method exists" \
    python -c "from agent.tools.rewrite_advisor import RewriteAdvisor; assert hasattr(RewriteAdvisor, '_llm_rewrite')"

check "_validate_rewrite method exists" \
    python -c "from agent.tools.rewrite_advisor import RewriteAdvisor; assert hasattr(RewriteAdvisor, '_validate_rewrite')"

check "_rule_based_rewrite method exists" \
    python -c "from agent.tools.rewrite_advisor import RewriteAdvisor; assert hasattr(RewriteAdvisor, '_rule_based_rewrite')"

check "_build_rag_context method exists" \
    python -c "from agent.tools.rewrite_advisor import RewriteAdvisor; assert hasattr(RewriteAdvisor, '_build_rag_context')"

check "_extract_diff_from_response method exists" \
    python -c "from agent.tools.rewrite_advisor import RewriteAdvisor; assert hasattr(RewriteAdvisor, '_extract_diff_from_response')"

check "_git_apply_check method exists" \
    python -c "from agent.tools.rewrite_advisor import RewriteAdvisor; assert hasattr(RewriteAdvisor, '_git_apply_check')"

check "apply_rewrite handles LLM unavailable gracefully" \
    python -c "
import tempfile, os, json
from agent.tools.rewrite_advisor import RewriteAdvisor
d = tempfile.mkdtemp()
os.makedirs(os.path.join(d, 'CVE-X', 'patches'))
with open(os.path.join(d, 'CVE-X', 'patches', 'original.patch'), 'w') as f:
    f.write('--- a/x.c\n+++ b/x.c\n@@ -1,1 +1,1 @@\n-old\n+new\n')
r = RewriteAdvisor(d, 'CVE-X', llm_client=None)
plan = {'decision': 'rewrite', 'strategy': 'context_drift'}
result = r.apply_rewrite(os.path.join(d, 'CVE-X', 'patches', 'original.patch'), plan, None, 1)
assert result['success'] == True
assert result['rewrite_source'] == 'rule'
"

check "apply_rewrite with plan decision=manual_required returns failure" \
    python -c "
import tempfile, os
from agent.tools.rewrite_advisor import RewriteAdvisor
d = tempfile.mkdtemp()
os.makedirs(os.path.join(d, 'CVE-X', 'patches'))
with open(os.path.join(d, 'CVE-X', 'patches', 'original.patch'), 'w') as f:
    f.write('--- a/x.c\n+++ b/x.c\n@@ -1,1 +1,1 @@\n-old\n+new\n')
r = RewriteAdvisor(d, 'CVE-X')
plan = {'decision': 'manual_required'}
result = r.apply_rewrite(os.path.join(d, 'CVE-X', 'patches', 'original.patch'), plan, None, 1)
assert result['success'] == False
"

check "SemanticValidator exists" \
    python -c "from agent.tools.semantic_validator import SemanticValidator"

check "SemanticValidator detects missing security check" \
    python -c "
from agent.tools.semantic_validator import SemanticValidator
sv = SemanticValidator()
orig = '@@ -100,6 +100,8 @@\n+       if (!sk)\n+               return -EINVAL;\n'
bad  = '@@ -100,6 +100,6 @@\n'
result = sv.validate(orig, bad)
assert result['valid'] == False
assert any('security' in i.lower() for i in result['issues'])
"

check "SemanticValidator passes identical patches" \
    python -c "
from agent.tools.semantic_validator import SemanticValidator
sv = SemanticValidator()
patch = '@@ -100,6 +100,8 @@\n+       if (!sk)\n+               return -EINVAL;\n'
assert sv.validate(patch, patch)['valid'] == True
"

check "create_rewrite_plan preserves manual gate even when LLM is available" \
    python -c "
import tempfile, os
from agent.tools.rewrite_advisor import RewriteAdvisor
d = tempfile.mkdtemp()
r = RewriteAdvisor(d, 'CVE-X')
# struct_abi with rewrite_allowed=False must remain manual_required with or without LLM
from unittest.mock import MagicMock
mock_llm = MagicMock()
mock_llm.ping.return_value = True
r2 = RewriteAdvisor(d, 'CVE-X', llm_client=mock_llm)
failure = {'category':'kpatch_limit','reason_code':'struct_or_data_change','retryable':False}
units = {'units':[{'change_id':'CU-001','file':'x.c','function':'f','rewrite_allowed':False}]}
plan_no_llm = r.create_rewrite_plan(failure, units, 1)
plan_llm    = r2.create_rewrite_plan(failure, units, 1)
assert plan_no_llm['decision'] == 'manual_required', 'without LLM should deny'
assert plan_llm['decision'] == 'manual_required', 'LLM must not override ABI safety gate'
"

echo ""

# ==================================================================
# Phase 5: RAG 系统
# ==================================================================
echo "── Phase 5: RAG 系统 ──"

check "KnowledgeBase exists" \
    python -c "from agent.rag.knowledge_base import KnowledgeBase, KnowledgeChunk"

check "KnowledgeRetriever exists" \
    python -c "from agent.rag.retriever import KnowledgeRetriever"

check "load_yaml_rules returns chunks" \
    python -c "from agent.rag.knowledge_base import KnowledgeBase; kb=KnowledgeBase(); n=kb.load_yaml_rules(); assert n >= 9, f'got {n}'"

check "load kernel API YAML returns chunks" \
    python -c "from agent.rag.knowledge_base import KnowledgeBase; kb=KnowledgeBase(); n=kb.load_kernel_api_yaml(); assert n == 38, f'got {n}'"

check "kernel_6.6_api.yaml exists" \
    test -f agent/knowledge/kernel_api/kernel_6.6_api.yaml

check "kernel_6.6_api.yaml has 38 entries" \
    python -c "import yaml; d=yaml.safe_load(open('agent/knowledge/kernel_api/kernel_6.6_api.yaml')); assert len(d)==38, f'got {len(d)}'"

check "chunk content is rich (contains matchers)" \
    python -c "
from agent.rag.knowledge_base import KnowledgeBase
kb = KnowledgeBase()
kb.load_yaml_rules()
# Check that chunks contain more than just category + action
for d in kb.documents:
    if 'failure_pattern' in str(d.metadata.get('type','')):
        assert len(d.content) > 20, f'chunk {d.id} too short: {d.content}'
        break
"

check "retriever returns results for query 'api_mismatch too many arguments'" \
    python -c "
from agent.rag.knowledge_base import KnowledgeBase
from agent.rag.retriever import KnowledgeRetriever
kb = KnowledgeBase()
kb.load_yaml_rules()
kb.load_kernel_api_yaml()
ret = KnowledgeRetriever(kb)
hits = ret.retrieve('api_mismatch too many arguments to function', top_k=3)
assert len(hits) > 0, 'no hits for api_mismatch query'
"

check "retriever returns API chunk for 'sock_create'" \
    python -c "
from agent.rag.knowledge_base import KnowledgeBase
from agent.rag.retriever import KnowledgeRetriever
kb = KnowledgeBase()
kb.load_yaml_rules()
kb.load_kernel_api_yaml()
ret = KnowledgeRetriever(kb)
hits = ret.retrieve('sock_create net parameter signature', top_k=3)
api_hits = [h for h in hits if 'api_' in h.id]
assert len(api_hits) > 0, 'no API chunk hit for sock_create'
"

check "retriever returns API chunk for 'setup_timer removed'" \
    python -c "
from agent.rag.knowledge_base import KnowledgeBase
from agent.rag.retriever import KnowledgeRetriever
kb = KnowledgeBase()
kb.load_yaml_rules()
kb.load_kernel_api_yaml()
ret = KnowledgeRetriever(kb)
hits = ret.retrieve('setup_timer timer_setup removed', top_k=3)
api_hits = [h for h in hits if 'api_' in h.id]
assert len(api_hits) > 0, 'no API chunk hit for setup_timer'
"

check "empty KB returns empty list" \
    python -c "
from agent.rag.knowledge_base import KnowledgeBase
from agent.rag.retriever import KnowledgeRetriever
kb = KnowledgeBase()
ret = KnowledgeRetriever(kb)
hits = ret.retrieve('anything', top_k=5)
assert hits == []
"

check "RAG context is built for sock_create failure" \
    python -c "
import tempfile, os
from agent.tools.rewrite_advisor import RewriteAdvisor
from agent.rag.knowledge_base import KnowledgeBase
from agent.rag.retriever import KnowledgeRetriever
kb = KnowledgeBase()
kb.load_yaml_rules()
kb.load_kernel_api_yaml()
ret = KnowledgeRetriever(kb)
d = tempfile.mkdtemp()
advisor = RewriteAdvisor(d, 'CVE-X', llm_client=None, retriever=ret)
failure = {'reason_code': 'api_mismatch', 'category': 'compile',
           'location': {'file': 'net/core.c', 'function': 'sock_create'}}
units = {'units': [{'change_id': 'CU-001', 'file': 'net/core.c',
        'function': 'sock_create', 'rewrite_allowed': True}]}
ctx = advisor._build_rag_context(failure, units)
assert 'sock_create' in ctx.lower(), f'RAG context missing sock_create: {ctx[:200]}'
assert len(ctx) > 100, f'RAG context too short: {len(ctx)} chars'
"

echo ""

# ==================================================================
# 全量测试
# ==================================================================
echo "── pytest: 全部单元测试 ──"
python -m pytest tests/ -v --tb=short 2>&1 | tail -3
pytest_exit=${PIPESTATUS[0]}
if [ "$pytest_exit" -eq 0 ]; then
    echo -e "  ${GREEN}[PASS]${NC} All tests passed"
else
    echo -e "  ${RED}[FAIL]${NC} Some tests failed (exit=$pytest_exit)"
    ((fail++)) || true
fi

echo ""
echo "============================================"
echo -e " Result: ${GREEN}${pass} passed${NC} / ${RED}${fail} failed${NC}"
echo "============================================"

if [ "$fail" -gt 0 ]; then
    exit 1
fi
