// ============================================================
// BAKOME-MailAI-Guard v1.0 — Version Compacte
// Fichier unique : bakome_mailai_guard.hpp
// C++17 | Header-only | 1200+ lignes | 0 dépendance externe
// Auteur : BAKOME — Goma, RDC
// ============================================================
//
// MODULES INTÉGRÉS :
//  1. Core Data Types (Email, Thread, Contact, CalendarEvent)
//  2. Cybersecurity Engine (phishing, malware, spoofing, BEC)
//  3. NLP Engine (ton, entités, résumé, lisibilité)
//  4. Mail Engine (recherche, labels, archivage)
//  5. Research Engine (Wikipedia, arXiv, Common Crawl)
//  6. Writing Engine (brouillons, amélioration, relecture)
//  7. Todo Engine (tâches liées aux emails)
//  8. API DLL Interface (FFI pour Python, Rust, Node.js)
// ============================================================

#ifndef BAKOME_MAILAI_GUARD_HPP
#define BAKOME_MAILAI_GUARD_HPP

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <chrono>
#include <queue>
#include <thread>
#include <mutex>
#include <regex>
#include <algorithm>
#include <cmath>
#include <sstream>
#include <fstream>
#include <functional>

namespace BAKOME {

// ============================================================
// 1. CORE DATA TYPES
// ============================================================

struct Email {
    std::string id, messageId, from, fromDomain, replyTo;
    std::vector<std::string> to, cc, bcc;
    std::string subject, body, bodySnippet, plainText, htmlContent;
    std::vector<std::string> attachmentIds, attachmentNames;
    std::string date;
    int64_t timestamp;
    std::vector<std::string> labels;
    bool isRead = false, isStarred = false, isSpam = false, isTrashed = false;
    int threadId = 0;
    std::string headers;
    std::map<std::string, std::string> headerMap;
};

struct Thread {
    int id;
    std::vector<Email> emails;
    std::string subject;
    int messageCount = 0;
    std::string firstMessageDate, lastMessageDate;
    int64_t lastMessageTimestamp = 0;
    std::vector<std::string> participants;
    bool hasAttachments = false, hasMalicious = false;
};

struct Contact {
    std::string name, email, domain;
    int64_t firstSeen = 0, lastSeen = 0;
    int messageCount = 0, receivedCount = 0, sentCount = 0;
    enum Importance { NEW_CONTACT, LOW, MEDIUM, HIGH, CRITICAL };
    Importance level = NEW_CONTACT;
    bool isBlocked = false, isVerified = false;
};

struct CalendarEvent {
    std::string id, calendarId, title, description, location;
    std::string startTime, endTime;
    int64_t startTimestamp = 0, endTimestamp = 0;
    std::vector<std::string> attendees;
    bool isRecurring = false;
};

struct TodoItem {
    std::string id, title, description;
    std::vector<int> linkedThreadIds;
    bool completed = false;
    int64_t createdAt = 0, dueDate = 0;
    int priority = 3;
};

struct Memory {
    std::string id, content, category;
    int64_t createdAt = 0, updatedAt = 0;
};

// ============================================================
// 2. CYBERSECURITY ENGINE
// ============================================================

struct SecurityThreat {
    enum ThreatType {
        PHISHING, MALWARE, RANSOMWARE, SPOOFED_SENDER,
        SUSPICIOUS_LINK, SUSPICIOUS_ATTACHMENT, DOMAIN_MISMATCH,
        CREDENTIAL_THEFT, SOCIAL_ENGINEERING,
        BUSINESS_EMAIL_COMPROMISE, SUPPLY_CHAIN_ATTACK, OTHER
    };
    ThreatType type = OTHER;
    float threatScore = 0.0f;
    std::string severity = "LOW";
    std::string description, remediation;
    int64_t detectedAt = 0;
    std::vector<std::string> indicators;
    bool requiresImmediateAction = false;
};

class CybersecurityEngine {
private:
    std::map<std::string, bool> blacklistedDomains;
    std::map<std::string, bool> maliciousUrls;
    std::vector<std::string> phishingKeywords = {
        "verify account", "confirm identity", "update payment", "urgent action",
        "click here", "suspicious activity", "compromised account",
        "confirm credentials", "temporary suspension"
    };
    std::vector<std::string> suspiciousExtensions = {
        ".exe", ".dll", ".scr", ".vbs", ".js", ".bat", ".cmd", ".zip", ".rar"
    };

public:
    CybersecurityEngine() {
        // Blacklist par défaut
        blacklistedDomains["malicious.com"] = true;
        blacklistedDomains["phishing.net"] = true;
        maliciousUrls["bit.ly"] = true;
        maliciousUrls["tinyurl.com"] = true;
    }

    SecurityThreat analyzeEmail(const Email& email) {
        SecurityThreat threat;
        float totalScore = 0.0f;
        int checks = 0;

        // 1. Vérification expéditeur
        std::string senderDomain = email.from.substr(email.from.find('@') + 1);
        if (senderDomain != email.fromDomain) {
            totalScore += 0.5f;
            threat.indicators.push_back("Domain mismatch: " + senderDomain);
            checks++;
        }

        // 2. Analyse en-têtes
        bool spfOk = email.headers.find("spf=pass") != std::string::npos;
        bool dkimOk = email.headers.find("dkim=pass") != std::string::npos;
        if (!spfOk || !dkimOk) { totalScore += 0.3f; checks++; }

        // 3. Analyse URLs
        auto urls = extractUrls(email.body);
        for (const auto& url : urls) {
            std::string domain = extractDomain(url);
            if (maliciousUrls.count(domain) || isShortenedUrl(url)) {
                totalScore += 0.4f;
                threat.indicators.push_back(url);
                checks++;
            }
        }

        // 4. Analyse contenu
        for (const auto& kw : phishingKeywords) {
            if (toLower(email.body).find(kw) != std::string::npos) {
                totalScore += 0.1f;
                threat.type = PHISHING;
                checks++;
            }
        }

        // 5. Réputation domaine
        if (blacklistedDomains.count(email.fromDomain)) {
            totalScore += 0.5f;
            threat.indicators.push_back("Blacklisted domain: " + email.fromDomain);
            checks++;
        }

        // 6. Détection BEC
        if (toLower(email.body).find("wire transfer") != std::string::npos ||
            toLower(email.body).find("urgent payment") != std::string::npos) {
            totalScore += 0.3f;
            threat.type = BUSINESS_EMAIL_COMPROMISE;
            checks++;
        }

        // Score final
        threat.threatScore = checks > 0 ? totalScore / checks : 0.0f;

        if (threat.threatScore >= 0.8f) {
            threat.severity = "CRITICAL";
            threat.requiresImmediateAction = true;
        } else if (threat.threatScore >= 0.6f) threat.severity = "HIGH";
        else if (threat.threatScore >= 0.4f) threat.severity = "MEDIUM";

        threat.detectedAt = now();
        return threat;
    }

private:
    std::vector<std::string> extractUrls(const std::string& text) {
        std::vector<std::string> urls;
        std::regex urlRegex(R"(https?://[^\s<>"]+)");
        auto begin = std::sregex_iterator(text.begin(), text.end(), urlRegex);
        auto end = std::sregex_iterator();
        for (auto it = begin; it != end; ++it) urls.push_back(it->str());
        return urls;
    }

    std::string extractDomain(const std::string& url) {
        size_t start = url.find("://");
        if (start == std::string::npos) start = 0; else start += 3;
        size_t end = url.find('/', start);
        return url.substr(start, (end == std::string::npos ? url.size() : end) - start);
    }

    bool isShortenedUrl(const std::string& url) {
        return url.find("bit.ly") != std::string::npos ||
               url.find("tinyurl") != std::string::npos ||
               url.find("t.co") != std::string::npos;
    }

    std::string toLower(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), ::tolower);
        return s;
    }

    int64_t now() {
        return std::chrono::system_clock::now().time_since_epoch().count();
    }
};

// ============================================================
// 3. NLP ENGINE
// ============================================================

class NLPEngine {
public:
    std::string analyzeTone(const Email& email) {
        std::string body = toLower(email.body);
        int urgent = countOccurrences(body, {"urgent", "asap", "immediately"});
        int angry = countOccurrences(body, {"unacceptable", "disappointed", "angry"});
        int friendly = countOccurrences(body, {"thanks", "appreciate", "grateful"});
        int professional = countOccurrences(body, {"dear", "regards", "sincerely"});

        if (urgent > professional) return "URGENT";
        if (angry > 0) return "ANGRY";
        if (friendly > 0) return "FRIENDLY";
        if (professional > 0) return "PROFESSIONAL";
        return "NEUTRAL";
    }

    std::vector<std::string> extractEntities(const Email& email) {
        std::vector<std::string> entities;
        // Emails
        std::regex emailRe(R"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})");
        for (auto it = std::sregex_iterator(email.body.begin(), email.body.end(), emailRe);
             it != std::sregex_iterator(); ++it)
            entities.push_back("EMAIL: " + it->str());
        // Montants
        std::regex amountRe(R"(\$[\d,]+\.?\d*)");
        for (auto it = std::sregex_iterator(email.body.begin(), email.body.end(), amountRe);
             it != std::sregex_iterator(); ++it)
            entities.push_back("AMOUNT: " + it->str());
        return entities;
    }

    std::string summarize(const Email& email) {
        std::vector<std::string> sentences = splitSentences(email.body);
        if (sentences.size() <= 2) return email.body.substr(0, 200);
        std::string summary;
        int take = std::max(1, (int)sentences.size() / 3);
        for (int i = 0; i < take && i < (int)sentences.size(); i++)
            summary += sentences[i] + " ";
        return summary;
    }

    int readabilityScore(const Email& email) {
        int words = 0, sentences = 0, syllables = 0;
        std::istringstream iss(email.body);
        std::string word;
        while (iss >> word) {
            words++;
            for (char c : word)
                if (c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u') syllables++;
        }
        sentences = std::count(email.body.begin(), email.body.end(), '.') +
                    std::count(email.body.begin(), email.body.end(), '!') +
                    std::count(email.body.begin(), email.body.end(), '?');
        if (words == 0 || sentences == 0) return 0;
        return std::max(0, std::min(100, (int)(206.835 - 1.015 * (words / sentences) - 84.6 * (syllables / (float)words))));
    }

private:
    std::string toLower(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), ::tolower);
        return s;
    }

    int countOccurrences(const std::string& text, const std::vector<std::string>& words) {
        int count = 0;
        for (const auto& w : words)
            if (text.find(w) != std::string::npos) count++;
        return count;
    }

    std::vector<std::string> splitSentences(const std::string& text) {
        std::vector<std::string> sentences;
        std::regex sentenceRe(R"([^.!?]+[.!?])");
        for (auto it = std::sregex_iterator(text.begin(), text.end(), sentenceRe);
             it != std::sregex_iterator(); ++it)
            sentences.push_back(it->str());
        return sentences;
    }
};

// ============================================================
// 4. MAIL ENGINE
// ============================================================

class MailEngine {
private:
    std::map<int, Thread> threads;
    std::map<std::string, Contact> contacts;
    std::vector<SecurityThreat> threats;

public:
    Thread searchThreads(const std::string& query, const std::string& filter = "") {
        Thread result;
        for (auto& [id, thread] : threads) {
            for (const auto& email : thread.emails) {
                float relevance = 0.0f;
                if (toLower(email.subject).find(toLower(query)) != std::string::npos) relevance += 0.5f;
                if (toLower(email.body).find(toLower(query)) != std::string::npos) relevance += 0.3f;
                if (!filter.empty()) {
                    if (filter.find("is:unread") != std::string::npos && !email.isRead) relevance += 0.2f;
                    if (filter.find("is:starred") != std::string::npos && email.isStarred) relevance += 0.2f;
                }
                if (relevance > 0.3f) result.emails.push_back(email);
            }
        }
        return result;
    }

    void labelThread(int threadId, const std::string& label) {
        if (threads.count(threadId) && !threads[threadId].emails.empty())
            threads[threadId].emails[0].labels.push_back(label);
    }

    void archiveThread(int threadId) {
        if (threads.count(threadId) && !threads[threadId].emails.empty()) {
            auto& labels = threads[threadId].emails[0].labels;
            labels.erase(std::remove(labels.begin(), labels.end(), "INBOX"), labels.end());
        }
    }

    void deleteThread(int threadId) {
        if (threads.count(threadId))
            for (auto& email : threads[threadId].emails) email.isTrashed = true;
    }

    void starThread(int threadId) {
        if (threads.count(threadId))
            for (auto& email : threads[threadId].emails) email.isStarred = true;
    }

    void markAsRead(int threadId) {
        if (threads.count(threadId))
            for (auto& email : threads[threadId].emails) email.isRead = true;
    }

    std::vector<SecurityThreat> getThreats() { return threats; }
    void addThreat(const SecurityThreat& t) { threats.push_back(t); }

    void addEmail(const Email& email) {
        if (!threads.count(email.threadId)) {
            Thread t;
            t.id = email.threadId;
            t.subject = email.subject;
            threads[email.threadId] = t;
        }
        threads[email.threadId].emails.push_back(email);
        threads[email.threadId].messageCount++;
    }

private:
    std::string toLower(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), ::tolower);
        return s;
    }
};

// ============================================================
// 5. RESEARCH ENGINE (Wikipedia + arXiv)
// ============================================================

class ResearchEngine {
private:
    std::map<std::string, std::string> cache;
    std::string cacheDir = "./bakome_cache";

public:
    struct ResearchResult {
        std::string title, summary, url, source;
        float relevance = 0.0f;
    };

    std::vector<ResearchResult> search(const std::string& query, const std::string& source = "all") {
        std::vector<ResearchResult> results;

        if (source == "all" || source == "wikipedia")
            searchWikipedia(query, results);
        if (source == "all" || source == "arxiv")
            searchArxiv(query, results);

        // Trier par pertinence
        std::sort(results.begin(), results.end(),
            [](const ResearchResult& a, const ResearchResult& b) { return a.relevance > b.relevance; });

        return results;
    }

    std::vector<std::string> suggestContext(const Email& email) {
        std::vector<std::string> suggestions;
        auto entities = NLPEngine().extractEntities(email);

        for (const auto& entity : entities) {
            if (entity.find("EMAIL:") != std::string::npos) {
                std::string domain = entity.substr(entity.find('@') + 1);
                suggestions.push_back("Rechercher des informations sur " + domain);
            }
            if (entity.find("AMOUNT:") != std::string::npos) {
                suggestions.push_back("Vérifier le contexte financier de " + entity);
            }
        }

        if (NLPEngine().analyzeTone(email) == "URGENT") {
            suggestions.push_back("Vérifier si cet email est une arnaque connue");
        }

        return suggestions;
    }

    std::string getWikipediaSummary(const std::string& title) {
        std::string key = "wiki:" + title;
        if (cache.count(key)) return cache[key];

        // Simulation d'une réponse Wikipedia (sans HTTP pour rester sans dépendance)
        std::string simulated = generateSimulatedWikiResponse(title);
        cache[key] = simulated;
        return simulated;
    }

    std::string getArxivAbstract(const std::string& query) {
        std::string key = "arxiv:" + query;
        if (cache.count(key)) return cache[key];

        std::string simulated = generateSimulatedArxivResponse(query);
        cache[key] = simulated;
        return simulated;
    }

private:
    void searchWikipedia(const std::string& query, std::vector<ResearchResult>& results) {
        std::string summary = getWikipediaSummary(query);
        if (!summary.empty()) {
            results.push_back({
                query,
                summary,
                "https://en.wikipedia.org/wiki/" + urlEncode(query),
                "Wikipedia",
                0.8f
            });
        }
    }

    void searchArxiv(const std::string& query, std::vector<ResearchResult>& results) {
        std::string abstract = getArxivAbstract(query);
        if (!abstract.empty()) {
            results.push_back({
                query + " (arXiv)",
                abstract,
                "https://arxiv.org/search/?query=" + urlEncode(query),
                "arXiv",
                0.6f
            });
        }
    }

    std::string generateSimulatedWikiResponse(const std::string& title) {
        // Simule une réponse pour démonstration
        if (toLower(title).find("cybersecurity") != std::string::npos)
            return "Cybersecurity is the practice of protecting systems, networks, and programs from digital attacks.";
        if (toLower(title).find("phishing") != std::string::npos)
            return "Phishing is a type of social engineering attack often used to steal user data, including login credentials.";
        if (toLower(title).find("email") != std::string::npos)
            return "Electronic mail (email) is a method of exchanging messages between people using electronic devices.";
        return "Information about '" + title + "' — [Wikipedia article summary]";
    }

    std::string generateSimulatedArxivResponse(const std::string& query) {
        if (toLower(query).find("machine learning") != std::string::npos)
            return "This paper presents a novel approach to machine learning for email security, achieving 98% detection rate.";
        if (toLower(query).find("nlp") != std::string::npos)
            return "Natural Language Processing techniques applied to email classification and threat detection.";
        return "Research paper related to '" + query + "' — [arXiv abstract]";
    }

    std::string urlEncode(const std::string& s) {
        std::string result;
        for (char c : s) {
            if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') result += c;
            else if (c == ' ') result += '_';
            else { result += '%'; result += "0123456789ABCDEF"[(c >> 4) & 0xF]; result += "0123456789ABCDEF"[c & 0xF]; }
        }
        return result;
    }

    std::string toLower(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), ::tolower);
        return s;
    }
};

// ============================================================
// 6. WRITING ENGINE
// ============================================================

class WritingEngine {
public:
    std::string generateDraft(const std::string& subject, const std::string& summary, bool formal = true) {
        std::string draft;
        draft += formal ? "Dear [Recipient],\n\n" : "Hi [Recipient],\n\n";
        draft += summary + "\n\n";
        draft += formal ? "Kind regards,\nBAKOME" : "Best,\nBAKOME";
        return draft;
    }

    std::string improveDraft(const std::string& draft) {
        std::string improved = draft;
        impr
