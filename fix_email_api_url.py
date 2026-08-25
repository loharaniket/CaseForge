import sys
f = 'apps/api/src/api/endpoints/email.py'
with open(f, 'r') as file:
    content = file.read()

imports = '''
from src.schemas.url_intel import CaseURLIntelligenceResponse, URLIntelligenceRecordSchema
from src.services.intelligence.url_service import AggregatedURLIntelligenceService, get_url_intel_service
'''

if 'CaseURLIntelligenceResponse' not in content:
    content = content.replace(
        'from src.schemas.domain_intel import',
        imports.strip() + '\nfrom src.schemas.domain_intel import'
    )

new_endpoints = '''

@router.post(
    "/{case_id}/url-intelligence",
    response_model=CaseURLIntelligenceResponse,
    status_code=status.HTTP_200_OK,
    responses={
        400: {"description": "Case processing failed"},
        401: {"description": "Authentication required"},
        404: {"description": "Case not found"},
    },
)
async def enrich_case_url_intelligence(
    case_id: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    case_access: CaseAccessService = Depends(get_case_access_service),
    url_service: AggregatedURLIntelligenceService = Depends(get_url_intel_service),
) -> CaseURLIntelligenceResponse:
    """Enriches all case URL infrastructure with URL Intelligence."""
    case_access.assert_can_modify_case(case_id=case_id, user=current_user, db=db)
    records = await url_service.analyze_case_url_intelligence(case_id=case_id, db=db)
    return CaseURLIntelligenceResponse(
        case_id=case_id,
        url_intelligence=[URLIntelligenceRecordSchema.model_validate(r) for r in records]
    )

@router.get(
    "/{case_id}/url-intelligence",
    response_model=CaseURLIntelligenceResponse,
    status_code=status.HTTP_200_OK,
    responses={
        401: {"description": "Authentication required"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Case not found"},
    },
)
def get_case_url_intelligence(
    case_id: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    case_access: CaseAccessService = Depends(get_case_access_service),
    url_service: AggregatedURLIntelligenceService = Depends(get_url_intel_service),
) -> CaseURLIntelligenceResponse:
    """Retrieves computed URL Intelligence for a case."""
    case_access.assert_can_view_case(case_id=case_id, user=current_user, db=db)
    records = url_service.get_case_url_intelligence(case_id=case_id, db=db)
    return CaseURLIntelligenceResponse(
        case_id=case_id,
        url_intelligence=[URLIntelligenceRecordSchema.model_validate(r) for r in records]
    )
'''
if 'enrich_case_url_intelligence' not in content:
    content += new_endpoints

with open(f, 'w') as file:
    file.write(content)
