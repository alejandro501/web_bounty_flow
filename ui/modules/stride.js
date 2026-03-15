import { MANUAL_RECON_QUESTIONS, MANUAL_WORKSPACE_QUESTIONS, STRIDE_LESSONS } from "../content/stride-data.js";

function manualReconStorageKey() {
  return "bflow_manual_recon_answers";
}

function loadManualReconAnswers() {
  try {
    return JSON.parse(localStorage.getItem(manualReconStorageKey()) || "{}");
  } catch {
    return {};
  }
}

function saveManualReconAnswers(answers) {
  localStorage.setItem(manualReconStorageKey(), JSON.stringify(answers));
}

function workspaceDisplayName(workspaceKey) {
  const map = {
    "high-level-questions": "High Level Questions",
    mechanisms: "Mechanisms",
    "notable-objects": "Notable Objects",
    "security-controls": "Security Controls",
    "threat-model": "Threat Model",
    spoofing: "S - Spoofing",
    tampering: "T - Tampering",
    repudiation: "R - Repudiation",
    "info-disclosure": "I - Information Disclosure",
    dos: "D - Denial of Service",
    eop: "E - Elevation of Privilege",
    workflow: "Workflow",
  };
  return map[workspaceKey] || workspaceKey;
}

function workspaceQuestionKey(workspaceKey, question) {
  return `${workspaceKey}::${question}`;
}

function manualHelpBullets(question, category) {
  if (!question) {
    return [];
  }
  return [
    `Why this matters: ${category} gaps often create exploitable trust assumptions.`,
    "How to investigate: capture concrete evidence (requests/responses, headers, and role context).",
    "What to write down: exploit path, impacted object/flow, and business impact if abused.",
  ];
}

function normalizeSearchText(value) {
  return String(value || "")
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[^\w\s-]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function getWorkspaceHelp(workspaceKey, question, category) {
  const generic = manualHelpBullets(question, category);
  const workspaceHelp = {
    spoofing: [
      "Validate identity at every boundary: token, session, and trust headers.",
      "Attempt impersonation with crafted claims, swapped identifiers, and replayed artifacts.",
      "Document whether spoofing crosses user, org, or service boundaries.",
    ],
    tampering: [
      "Try modifying state inputs server expects to be immutable.",
      "Probe race/replay paths around critical workflow transitions.",
      "Track data integrity failures and affected business objects.",
    ],
    repudiation: [
      "Verify sensitive actions create immutable and attributable audit records.",
      "Look for missing request IDs, actor context, or timing integrity.",
      "Record what an attacker can deny and why defenders cannot prove otherwise.",
    ],
    "info-disclosure": [
      "Map all fields returned by APIs and identify overexposure.",
      "Check error/debug/log channels for secrets or private metadata.",
      "Quantify disclosure scope: single record, tenant-wide, or platform-wide.",
    ],
    dos: [
      "Identify high-cost endpoints lacking strict quota/complexity controls.",
      "Test amplification and queue saturation without harming production.",
      "Capture blast radius and recovery behavior for critical user flows.",
    ],
    eop: [
      "Test authorization consistency across UI, API, and background paths.",
      "Chain horizontal access and role flaws toward admin capabilities.",
      "Describe final privilege gained and what controls failed.",
    ],
    "threat-model": [
      "Express preconditions, steps, and control bypass clearly.",
      "Tie each threat to measurable customer/business impact.",
      "List validation criteria for mitigation completion.",
    ],
  };
  return workspaceHelp[workspaceKey] || generic;
}

export function initStrideFeature({
  strideTabs,
  strideSections,
  learnQuestion,
  learnAnswers,
  learnPrev,
  learnNext,
  learnIndex,
  strideAnswerText,
  strideAnswerStatus,
  strideExportAnswers,
  manualWorkspaceRoots,
  escapeHTML,
}) {
  let activeStrideKey = "overview";
  let learnSlideIndex = 0;
  let strideSaveTimer = null;
  const manualWorkspaceState = {};

  function renderStrideLearning() {
    if (!learnQuestion || !learnAnswers || !learnIndex) {
      return;
    }
    const lessons = STRIDE_LESSONS[activeStrideKey] || [];
    if (lessons.length === 0) {
      learnQuestion.textContent = "No learning prompts for this section yet.";
      learnAnswers.innerHTML = "";
      learnIndex.textContent = "0 / 0";
      return;
    }
    if (learnSlideIndex < 0) {
      learnSlideIndex = 0;
    }
    if (learnSlideIndex >= lessons.length) {
      learnSlideIndex = lessons.length - 1;
    }
    const lesson = lessons[learnSlideIndex];
    learnQuestion.textContent = lesson.question;
    learnAnswers.innerHTML = (lesson.answers || []).map((answer) => `<li>${escapeHTML(answer)}</li>`).join("");
    learnIndex.textContent = `${learnSlideIndex + 1} / ${lessons.length}`;
  }

  function strideAnswerStorageKey() {
    return `bflow_stride_answer_${activeStrideKey}`;
  }

  function loadStrideAnswer() {
    if (!strideAnswerText) {
      return;
    }
    strideAnswerText.value = localStorage.getItem(strideAnswerStorageKey()) || "";
    if (strideAnswerStatus) {
      strideAnswerStatus.textContent = "Loaded section notes.";
    }
  }

  function exportAllAnswersMarkdown() {
    const answersMap = loadManualReconAnswers();
    const lines = [];
    lines.push("# STRIDE Answers Export", "", `Generated: ${new Date().toISOString()}`, "");
    for (const [workspaceKey, workspaceData] of Object.entries(MANUAL_WORKSPACE_QUESTIONS)) {
      const allQuestions = [];
      for (const section of workspaceData) {
        for (const question of section.questions || []) {
          allQuestions.push({ category: section.category, question });
        }
      }
      lines.push(`## ${workspaceDisplayName(workspaceKey)}`, "");
      let workspaceHasContent = false;
      for (const item of allQuestions) {
        const key = workspaceQuestionKey(workspaceKey, item.question);
        const answers = Array.isArray(answersMap[key]) ? answersMap[key] : [];
        if (answers.length === 0) {
          continue;
        }
        workspaceHasContent = true;
        lines.push(`### ${item.question}`, `Category: ${item.category}`, "");
        answers.forEach((entry, idx) => {
          lines.push(`${idx + 1}. ${entry.text || ""}`);
          if (entry.created_at) {
            lines.push(`   - Saved: ${entry.created_at}`);
          }
        });
        lines.push("");
      }
      const note = localStorage.getItem(`bflow_stride_answer_${workspaceKey}`) || "";
      if (note.trim()) {
        workspaceHasContent = true;
        lines.push("### Workspace Notes", note.trim(), "");
      }
      if (!workspaceHasContent) {
        lines.push("_No answers saved._", "");
      }
    }
    const blob = new Blob([lines.join("\n")], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `stride_answers_${Date.now()}.md`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }

  function initializeManualRecon() {
    for (const root of manualWorkspaceRoots) {
      const workspaceKey = root.dataset.workspace;
      const questionBank = MANUAL_WORKSPACE_QUESTIONS[workspaceKey] || [];
      if (!workspaceKey || questionBank.length === 0) {
        continue;
      }

      const search = root.querySelector(".manual-recon-search");
      const categories = root.querySelector(".manual-recon__categories");
      const questionTitle = root.querySelector(".manual-recon-question-title");
      const questionCategory = root.querySelector(".manual-recon-question-category");
      const helpList = root.querySelector(".manual-recon-help-list");
      const answersList = root.querySelector(".manual-recon__answers-list");
      const addAnswer = root.querySelector(".manual-recon-add-answer");
      const answerInput = root.querySelector(".manual-recon-answer-input");
      const saveAnswer = root.querySelector(".manual-recon-save-answer");
      const answerStatus = root.querySelector(".manual-recon-answer-status");
      if (!categories || !questionTitle || !questionCategory || !helpList || !answersList || !answerInput) {
        continue;
      }

      manualWorkspaceState[workspaceKey] = manualWorkspaceState[workspaceKey] || { query: "", selectedQuestion: "" };
      const state = manualWorkspaceState[workspaceKey];

      const getFiltered = () => {
        const needle = normalizeSearchText(state.query || "");
        if (!needle) {
          return questionBank;
        }
        const terms = needle.split(" ").filter(Boolean);
        const filtered = [];
        for (const entry of questionBank) {
          const categoryText = normalizeSearchText(entry.category);
          const matched = entry.questions.filter((question) => {
            const questionText = normalizeSearchText(question);
            return terms.every((term) => questionText.includes(term) || categoryText.includes(term));
          });
          if (matched.length > 0) {
            filtered.push({ category: entry.category, questions: matched });
          }
        }
        return filtered;
      };

      const firstQuestion = (filtered) => {
        for (const entry of filtered) {
          if (entry.questions.length > 0) {
            return entry.questions[0];
          }
        }
        return "";
      };

      const findCategory = (question) => {
        for (const entry of questionBank) {
          if (entry.questions.includes(question)) {
            return entry.category;
          }
        }
        return "";
      };

      const renderAnswers = () => {
        if (!state.selectedQuestion) {
          answersList.textContent = "No answers yet. Add your first answer below.";
          return;
        }
        const map = loadManualReconAnswers();
        const key = workspaceQuestionKey(workspaceKey, state.selectedQuestion);
        const answers = Array.isArray(map[key]) ? map[key] : [];
        if (answers.length === 0) {
          answersList.textContent = "No answers yet. Add your first answer below.";
          return;
        }
        answersList.innerHTML = answers.map((entry, index) => `
          <article class="manual-recon__answer-item">
            <button type="button" class="manual-recon__answer-delete" data-answer-index="${index}" aria-label="Delete answer" title="Delete answer">&#128465;</button>
            <div class="manual-recon__answer-text">${escapeHTML(entry.text || "")}</div>
            <small>${escapeHTML(entry.created_at || "")}</small>
          </article>
        `).join("");
      };

      const renderDetails = () => {
        if (!state.selectedQuestion) {
          questionTitle.textContent = "Select a question";
          questionCategory.textContent = "";
          helpList.innerHTML = "";
          renderAnswers();
          return;
        }
        const category = findCategory(state.selectedQuestion);
        questionTitle.textContent = state.selectedQuestion;
        questionCategory.textContent = category;
        helpList.innerHTML = getWorkspaceHelp(workspaceKey, state.selectedQuestion, category).map((line) => `<li>${escapeHTML(line)}</li>`).join("");
        renderAnswers();
      };

      const renderWorkspace = () => {
        const filtered = getFiltered();
        const visibleQuestions = new Set(filtered.flatMap((entry) => entry.questions));
        if (!state.selectedQuestion || !visibleQuestions.has(state.selectedQuestion)) {
          state.selectedQuestion = firstQuestion(filtered);
        }
        if (filtered.length === 0) {
          categories.innerHTML = '<p class="muted">No matching questions.</p>';
          renderDetails();
          return;
        }
        categories.innerHTML = filtered.map((entry) => {
          const buttons = entry.questions.map((question) => {
            const active = state.selectedQuestion === question ? "is-active" : "";
            return `<button type="button" class="manual-recon__question ${active}" data-manual-question="${escapeHTML(question)}">${escapeHTML(question)}</button>`;
          }).join("");
          return `<section class="manual-recon__category"><h5 class="manual-recon__category-title">${escapeHTML(entry.category)}</h5>${buttons}</section>`;
        }).join("");
        renderDetails();
      };

      categories.addEventListener("click", (event) => {
        const button = event.target.closest(".manual-recon__question");
        if (!button) {
          return;
        }
        state.selectedQuestion = button.dataset.manualQuestion || "";
        renderWorkspace();
      });

      search?.addEventListener("input", () => {
        state.query = search.value || "";
        renderWorkspace();
      });

      addAnswer?.addEventListener("click", () => {
        answerInput.focus();
      });

      answersList.addEventListener("click", (event) => {
        const button = event.target.closest(".manual-recon__answer-delete");
        if (!button || !state.selectedQuestion) {
          return;
        }
        const index = Number.parseInt(button.dataset.answerIndex || "", 10);
        if (!Number.isInteger(index) || index < 0) {
          return;
        }
        const map = loadManualReconAnswers();
        const key = workspaceQuestionKey(workspaceKey, state.selectedQuestion);
        const current = Array.isArray(map[key]) ? map[key] : [];
        if (index >= current.length) {
          return;
        }
        current.splice(index, 1);
        if (current.length > 0) {
          map[key] = current;
        } else {
          delete map[key];
        }
        saveManualReconAnswers(map);
        if (answerStatus) {
          answerStatus.textContent = "Answer deleted.";
        }
        renderAnswers();
      });

      const saveCurrentAnswer = () => {
        const text = (answerInput.value || "").trim();
        if (!text || !state.selectedQuestion) {
          return;
        }
        const map = loadManualReconAnswers();
        const key = workspaceQuestionKey(workspaceKey, state.selectedQuestion);
        const current = Array.isArray(map[key]) ? map[key] : [];
        current.unshift({ text, created_at: new Date().toLocaleString() });
        map[key] = current;
        saveManualReconAnswers(map);
        answerInput.value = "";
        if (answerStatus) {
          answerStatus.textContent = "Answer saved.";
        }
        renderAnswers();
      };

      saveAnswer?.addEventListener("click", saveCurrentAnswer);
      answerInput.addEventListener("keydown", (event) => {
        if (!(event.ctrlKey || event.metaKey) || event.key !== "Enter") {
          return;
        }
        event.preventDefault();
        saveCurrentAnswer();
      });

      state.selectedQuestion = firstQuestion(questionBank);
      renderWorkspace();
    }
  }

  strideTabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      const key = tab.dataset.strideTab;
      if (!key) {
        return;
      }
      strideTabs.forEach((node) => node.classList.remove("is-active"));
      tab.classList.add("is-active");
      strideSections.forEach((section) => {
        section.classList.toggle("is-active", section.dataset.strideContent === key);
      });
      activeStrideKey = key;
      learnSlideIndex = 0;
      renderStrideLearning();
      loadStrideAnswer();
    });
  });

  learnPrev?.addEventListener("click", () => {
    learnSlideIndex -= 1;
    renderStrideLearning();
  });

  learnNext?.addEventListener("click", () => {
    learnSlideIndex += 1;
    renderStrideLearning();
  });

  strideAnswerText?.addEventListener("input", () => {
    if (strideSaveTimer) {
      clearTimeout(strideSaveTimer);
    }
    strideSaveTimer = setTimeout(() => {
      localStorage.setItem(strideAnswerStorageKey(), strideAnswerText.value);
      if (strideAnswerStatus) {
        strideAnswerStatus.textContent = "Saved locally.";
      }
    }, 250);
  });

  strideExportAnswers?.addEventListener("click", exportAllAnswersMarkdown);

  renderStrideLearning();
  loadStrideAnswer();
  initializeManualRecon();
}
