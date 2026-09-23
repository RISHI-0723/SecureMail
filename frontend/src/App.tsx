/**
 * SecureMailScope - Main Application
 * AI-Assisted Cryptographic Security Posture Assessment
 */
import { useEffect, useState } from 'react';
import { api, getAccessToken, clearTokens } from '@/services/api';
import type { UserInfo } from '@/types';
import { Layout, type Page } from '@/components/Layout';
import { LoginPage } from '@/pages/LoginPage';
import { SignUpPage } from '@/pages/SignUpPage';
import { DashboardPage } from '@/pages/DashboardPage';
import { CasesPage } from '@/pages/CasesPage';
import { CaseDetailPage } from '@/pages/CaseDetailPage';
import { SettingsPage } from '@/pages/SettingsPage';
import { AdminPage } from '@/pages/AdminPage';
import { FindingsPage } from '@/pages/FindingsPage';
import { ReportsPage } from '@/pages/ReportsPage';

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(!!getAccessToken());
  const [currentUser, setCurrentUser] = useState<UserInfo | null>(null);
  const [authLoading, setAuthLoading] = useState(true);
  const [currentPage, setCurrentPage] = useState<Page>('dashboard');
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null);
  const [showSignUp, setShowSignUp] = useState(false);

  useEffect(() => {
    if (isAuthenticated) {
      fetchCurrentUser();
    } else {
      setAuthLoading(false);
    }
  }, [isAuthenticated]);

  const fetchCurrentUser = async () => {
    try {
      const user = await api.getCurrentUser();
      setCurrentUser(user);
    } catch (err) {
      // If user fetch fails, clear auth state
      handleLogout();
    } finally {
      setAuthLoading(false);
    }
  };

  const handleLoginSuccess = () => {
    setIsAuthenticated(true);
    setAuthLoading(true);
    setShowSignUp(false);
  };

  const handleSignUpSuccess = () => {
    setIsAuthenticated(true);
    setAuthLoading(true);
    setShowSignUp(false);
  };

  const handleLogout = () => {
    clearTokens();
    setIsAuthenticated(false);
    setCurrentUser(null);
    setCurrentPage('dashboard');
    setSelectedCaseId(null);
    setAuthLoading(false);
    setShowSignUp(false);
  };

  const handleNavigate = (page: Page) => {
    setCurrentPage(page);
    if (page !== 'case-detail') {
      setSelectedCaseId(null);
    }
  };

  const handleSelectCase = (caseId: string) => {
    setSelectedCaseId(caseId);
    setCurrentPage('case-detail');
  };

  const handleBackToCases = () => {
    setSelectedCaseId(null);
    setCurrentPage('cases');
  };

  // Show login/signup page if not authenticated
  if (!isAuthenticated) {
    if (showSignUp) {
      return (
        <SignUpPage
          onSignUpSuccess={handleSignUpSuccess}
          onSwitchToLogin={() => setShowSignUp(false)}
        />
      );
    }
    return (
      <LoginPage
        onLoginSuccess={handleLoginSuccess}
        onSwitchToSignUp={() => setShowSignUp(true)}
      />
    );
  }

  // Show loading while fetching user
  if (authLoading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <div className="text-center">
          <div className="w-12 h-12 border-4 border-cyan-400 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
          <p className="text-slate-400">Loading...</p>
        </div>
      </div>
    );
  }

  const renderContent = () => {
    switch (currentPage) {
      case 'dashboard':
        return <DashboardPage onNavigate={handleNavigate} />;
      case 'cases':
        return <CasesPage onSelectCase={handleSelectCase} />;
      case 'case-detail':
        return selectedCaseId ? (
          <CaseDetailPage caseId={selectedCaseId} onBack={handleBackToCases} />
        ) : (
          <CasesPage onSelectCase={handleSelectCase} />
        );
      case 'findings':
        return <FindingsPage />;
      case 'reports':
        return <ReportsPage />;
      case 'settings':
        return <SettingsPage currentUser={currentUser} />;
      case 'admin':
        return currentUser?.role === 'ADMIN' ? (
          <AdminPage />
        ) : (
          <div className="text-center py-12">
            <p className="text-slate-400">Access denied. Admin privileges required.</p>
          </div>
        );
      default:
        return <DashboardPage onNavigate={handleNavigate} />;
    }
  };

  return (
    <Layout
      currentPage={currentPage}
      onNavigate={handleNavigate}
      currentUser={currentUser}
      onLogout={handleLogout}
    >
      {renderContent()}
    </Layout>
  );
}

export default App;
