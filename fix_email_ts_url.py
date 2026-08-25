import sys
f = 'apps/web/src/lib/api/email.ts'
with open(f, 'r') as file:
    content = file.read()

new_content = content + '''
export async function getCaseURLIntelligence(caseId: string) {
  return apiClient.get<unknown>(`api/email/${caseId}/url-intelligence`);
}

export async function enrichCaseURLIntelligence(caseId: string) {
  return apiClient.post<unknown>(`api/email/${caseId}/url-intelligence`, undefined);
}
'''
with open(f, 'w') as file:
    file.write(new_content)
