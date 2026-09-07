import { CampaignResponse } from "@/types";
import { apiClient } from "./client";
import {
  CaseGeoInfrastructureResponse,
  CaseIOCListResponse,
  CaseThreatIntelResponse,
  EmailUploadResponse,
  HeaderForensicsResponse,
  ParsedEmail,
  RiskAssessmentResponse,
  ThreatAssessmentResponse,
  ForensicTimelineResponse,
  InvestigationGraphResponse,
  CaseEvidenceListResponse,
  CaseEvidenceVerificationResponse,
  CaseThreatGraphResponse,
  CaseAnalysisHistoryResponse,
  InvestigationConclusionResponse,
  AnalysisStatusResponse,
} from "@/types";

export async function uploadEmailFile(file: File): Promise<EmailUploadResponse> {
  const formData = new FormData();
  formData.append("file", file);
  return apiClient.postFormData<EmailUploadResponse>("api/email/upload", formData);
}

export async function getAnalysisStatus(caseId: string): Promise<AnalysisStatusResponse> {
  return apiClient.get<AnalysisStatusResponse>(`api/email/${caseId}/analysis/status`);
}

export async function getParsedEmail(caseId: string): Promise<ParsedEmail> {
  return apiClient.get<ParsedEmail>(`api/email/${caseId}/parsed`);
}

export async function parseEmailCase(caseId: string): Promise<ParsedEmail> {
  return apiClient.post<ParsedEmail>(`api/email/${caseId}/parse`);
}

export async function getThreatAnalysis(caseId: string): Promise<ThreatAssessmentResponse> {
  return apiClient.get<ThreatAssessmentResponse>(`api/email/${caseId}/threat-analysis`);
}

export async function getHeaderForensics(caseId: string): Promise<HeaderForensicsResponse> {
  return apiClient.get<HeaderForensicsResponse>(`api/email/${caseId}/header-forensics`);
}

export async function getCaseRisk(caseId: string): Promise<RiskAssessmentResponse> {
  return apiClient.get<RiskAssessmentResponse>(`api/email/${caseId}/risk-assessment`);
}

export async function getCaseIOCs(caseId: string): Promise<CaseIOCListResponse> {
  return apiClient.get<CaseIOCListResponse>(`api/email/${caseId}/iocs`);
}

export async function getCaseThreatIntel(caseId: string): Promise<CaseThreatIntelResponse> {
  return apiClient.get<CaseThreatIntelResponse>(`api/email/${caseId}/threat-intel`);
}

export async function getCaseGeoInfrastructure(caseId: string): Promise<CaseGeoInfrastructureResponse> {
  return apiClient.get<CaseGeoInfrastructureResponse>(`api/email/${caseId}/geo-infrastructure`);
}

export async function getCaseTimeline(caseId: string): Promise<ForensicTimelineResponse> {
  return apiClient.get<ForensicTimelineResponse>(`api/email/${caseId}/timeline`);
}

export async function getCaseGraph(caseId: string): Promise<InvestigationGraphResponse> {
  return apiClient.get<InvestigationGraphResponse>(`api/email/${caseId}/graph`);
}

export async function syncCaseGraph(caseId: string): Promise<InvestigationGraphResponse> {
  return apiClient.post<InvestigationGraphResponse>(`api/email/${caseId}/graph/sync`);
}

export async function downloadInvestigationReport(caseId: string): Promise<void> {
  const blob = await apiClient.downloadBlob(`api/email/${caseId}/report/pdf`);
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `CaseForge_Investigation_Report_${caseId.slice(0, 8)}.pdf`;
  document.body.appendChild(a);
  a.click();
  window.URL.revokeObjectURL(url);
  document.body.removeChild(a);
}

export async function getCaseReportData(caseId: string): Promise<Record<string, unknown>> {
  return apiClient.get<Record<string, unknown>>(`api/email/${caseId}/report/data`);
}

export async function getCaseEvidence(caseId: string): Promise<CaseEvidenceListResponse> {
  return apiClient.get<CaseEvidenceListResponse>(`api/email/${caseId}/evidence`);
}

export async function verifyCaseEvidence(caseId: string): Promise<CaseEvidenceVerificationResponse> {
  return apiClient.post<CaseEvidenceVerificationResponse>(`api/email/${caseId}/evidence/verify`);
}

export async function getCaseAnalysisHistory(caseId: string): Promise<CaseAnalysisHistoryResponse> {
  return apiClient.get<CaseAnalysisHistoryResponse>(`api/email/${caseId}/analysis-history`);
}

export async function getCaseThreatGraph(caseId: string): Promise<CaseThreatGraphResponse> {
  return apiClient.get<CaseThreatGraphResponse>(`api/email/${caseId}/graph`);
}

export async function getCaseIPIntelligence(caseId: string) {
  return apiClient.get<unknown>(`api/email/${caseId}/ip-intelligence`);
}

export async function enrichCaseIPIntelligence(caseId: string) {
  return apiClient.post<unknown>(`api/email/${caseId}/ip-intelligence`, undefined);
}


export async function getCaseDomainIntelligence(caseId: string) {
  return apiClient.get<unknown>(`api/email/${caseId}/domain-intelligence`);
}

export async function enrichCaseDomainIntelligence(caseId: string) {
  return apiClient.post<unknown>(`api/email/${caseId}/domain-intelligence`, undefined);
}

export async function getCaseURLIntelligence(caseId: string) {
  return apiClient.get<unknown>(`api/email/${caseId}/url-intelligence`);
}

export async function enrichCaseURLIntelligence(caseId: string) {
  return apiClient.post<unknown>(`api/email/${caseId}/url-intelligence`, undefined);
}

export async function getCaseCampaigns(caseId: string): Promise<CampaignResponse[]> {
    return apiClient.get<CampaignResponse[]>(`api/email/${caseId}/campaigns`);
}

export async function getInvestigationConclusion(caseId: string): Promise<InvestigationConclusionResponse> {
  return apiClient.get<InvestigationConclusionResponse>(`api/email/${caseId}/conclusion`);
}
