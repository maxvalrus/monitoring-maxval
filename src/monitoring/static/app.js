(() => {
  const root = document.documentElement;
  root.dataset.theme = localStorage.getItem("monitoring-theme") || "auto";

  const showToast = (message, kind = "success") => {
    if (!message) return;
    const region = document.querySelector("[data-toast-region]");
    if (!region) return;
    const toast = document.createElement("div");
    toast.className = `toast toast-${kind}`;
    toast.setAttribute("role", kind === "error" ? "alert" : "status");
    toast.textContent = message;
    region.append(toast);
    requestAnimationFrame(() => toast.classList.add("is-visible"));
    window.setTimeout(() => {
      toast.classList.remove("is-visible");
      window.setTimeout(() => toast.remove(), 220);
    }, 4200);
  };

  const errorMessage = (detail, fallback) => {
    if (typeof detail === "string" && detail.trim()) return detail;
    if (Array.isArray(detail)) {
      const messages = detail
        .map((item) => typeof item?.msg === "string" ? item.msg : "")
        .filter(Boolean);
      if (messages.length) return messages.join("; ");
    }
    if (detail && typeof detail === "object" && typeof detail.message === "string") {
      return detail.message;
    }
    return fallback;
  };


  const syncDocumentShell = (documentCopy) => {
    if (!documentCopy?.body) return;
    document.body.className = documentCopy.body.className;
    const currentNav = document.querySelector(".topbar nav");
    const nextNav = documentCopy.querySelector(".topbar nav");
    if (currentNav && nextNav) currentNav.replaceWith(document.importNode(nextNav, true));
  };

  const showDefaultPasswordWarning = () => {
    const marker = document.querySelector("[data-default-password-warning]");
    const region = document.querySelector("[data-toast-region]");
    if (!marker || !region || region.querySelector(".toast-warning-password")) return;
    const toast = document.createElement("div");
    toast.className = "toast toast-warning-password";
    toast.setAttribute("role", "alert");

    const message = document.createElement("div");
    message.className = "toast-message";
    const strong = document.createElement("strong");
    strong.textContent = "Используется стандартный пароль admin";
    const text = document.createElement("span");
    text.textContent = "Смените пароль администратора.";
    message.append(strong, text);

    const actions = document.createElement("div");
    actions.className = "toast-actions";
    const link = document.createElement("a");
    link.className = "button button-secondary";
    link.href = marker.dataset.passwordUrl || "/users";
    link.textContent = "Сменить пароль";
    const close = document.createElement("button");
    close.className = "toast-close";
    close.type = "button";
    close.setAttribute("aria-label", "Закрыть предупреждение");
    close.textContent = "×";
    close.addEventListener("click", () => toast.remove());
    actions.append(link, close);

    toast.append(message, actions);
    region.append(toast);
    requestAnimationFrame(() => toast.classList.add("is-visible"));
  };

  const initTargetForms = () => {
    document.querySelectorAll(".target-form").forEach((form) => {
      const checker = form.querySelector("[data-checker-select]");
      const portField = form.querySelector("[data-port-field]");
      const port = form.querySelector("[data-port-input]");
      const pathField = form.querySelector("[data-path-field]");
      const addressField = form.querySelector("[data-address-field]");
      const dnsOptions = form.querySelector("[data-dns-options]");
      const directoryOptions = form.querySelector("[data-directory-options]");
      const directoryCredentials = form.querySelector("[data-directory-smb-credentials]");
      const deepOptions = form.querySelector("[data-http-deep-options]");
      const tlsOptions = form.querySelector("[data-tls-monitor-options]");
      const tlsEnabled = form.querySelector("[data-tls-monitor-enabled]");
      const currentHttpStatus = form.querySelector("[data-current-http-status]");
      if (!checker || !portField || !port || checker.dataset.portReady) return;
      checker.dataset.portReady = "true";
      const syncPort = (applyDefault) => {
        const name = checker.value;
        const isIcmp = name === "icmp";
        const isDns = name === "dns";
        const isDirectory = name === "directory";
        portField.hidden = isIcmp || isDns || isDirectory;
        port.disabled = isIcmp || isDns || isDirectory;
        port.required = !isIcmp && !isDns && !isDirectory;
        if (isIcmp || isDns || isDirectory) port.value = "";
        else if (applyDefault && name === "http") port.value = "80";
        else if (applyDefault && name === "https") port.value = "443";
        else if (applyDefault && name === "rtsp") port.value = "554";
        else if (!port.value) port.value = name === "rtsp" ? "554" : "80";
        if (pathField) pathField.hidden = !(name === "http" || name === "https");
        if (addressField) addressField.hidden = isDns || isDirectory;
        if (dnsOptions) dnsOptions.hidden = !isDns;
        if (directoryOptions) {
          directoryOptions.hidden = !isDirectory;
          const directoryPath = directoryOptions.querySelector("[name='directory_path']");
          const syncDirectoryCredentials = () => {
            if (directoryCredentials) directoryCredentials.hidden = !isDirectory || !directoryPath?.value.startsWith("\\\\");
          };
          syncDirectoryCredentials();
          if (directoryPath && !directoryPath.dataset.credentialsReady) {
            directoryPath.dataset.credentialsReady = "true";
            directoryPath.addEventListener("input", () => {
              if (directoryCredentials) directoryCredentials.hidden = !directoryPath.value.startsWith("\\\\");
            });
          }
        }
        if (deepOptions) {
          const isHttp = name === "http" || name === "https";
          deepOptions.hidden = !isHttp;
          if (!isHttp) {
            deepOptions.querySelectorAll("[data-http-deep-field]").forEach((field) => { field.value = ""; });
          }
        }
        if (tlsOptions) {
          const isHttps = name === "https";
          tlsOptions.hidden = !isHttps;
          if (!isHttps && tlsEnabled) tlsEnabled.checked = false;
          tlsOptions.querySelectorAll("[data-tls-monitor-field]").forEach((field) => {
            field.disabled = !isHttps || !tlsEnabled?.checked;
          });
        }
      };
      syncPort(false);
      checker.addEventListener("change", () => syncPort(true));
      tlsEnabled?.addEventListener("change", () => syncPort(false));
      if (currentHttpStatus && !currentHttpStatus.dataset.ready) {
        currentHttpStatus.dataset.ready = "true";
        currentHttpStatus.addEventListener("click", async () => {
          const targetId = form.dataset.targetId;
          if (!targetId || !(checker.value === "http" || checker.value === "https")) {
            showToast("Текущий код доступен только для HTTP или HTTPS", "error");
            return;
          }
          currentHttpStatus.disabled = true;
          try {
            const response = await fetch(`/targets/${encodeURIComponent(targetId)}/checks/current-http-status`, {
              method: "POST",
              credentials: "same-origin",
              headers: { "X-Requested-With": "Monitoring-Maxval" },
              body: new FormData(form)
            });
            const payload = await response.json().catch(() => ({}));
            if (!response.ok) throw new Error(payload.detail || "Не удалось получить HTTP-код");
            const expectedStatus = form.querySelector("[name='expected_status']");
            if (expectedStatus) expectedStatus.value = String(payload.status_code);
            const maxResponse = form.querySelector("[name='max_response_ms']");
            if (maxResponse && typeof payload.latency_ms === "number") {
              maxResponse.value = String(Math.round(payload.latency_ms * 10) / 10);
            }
            const latency = typeof payload.latency_ms === "number"
              ? `; время ответа: ${Math.round(payload.latency_ms * 10) / 10} мс`
              : "";
            showToast(`Текущий HTTP-код: ${payload.status_code}${latency}`);
          } catch (error) {
            showToast(error.message || "Не удалось получить HTTP-код", "error");
          } finally {
            currentHttpStatus.disabled = false;
          }
        });
      }
    });
  };

  let autoRefreshTimer = null;
  const refreshPageContent = async () => {
    const portalDetailsOpen = document.querySelector(".portal-details")?.open === true;
    try {
      const response = await fetch(window.location.href, {
        headers: { "X-Requested-With": "Monitoring-Maxval" },
        credentials: "same-origin"
      });
      if (!response.ok) throw new Error("Страница временно недоступна");
      const documentCopy = new DOMParser().parseFromString(await response.text(), "text/html");
      const nextMain = documentCopy.querySelector("main.container");
      const currentMain = document.querySelector("main.container");
      if (!nextMain || !currentMain) throw new Error("Не удалось обновить страницу");
      currentMain.replaceWith(nextMain);
      document.title = documentCopy.title;
      syncDocumentShell(documentCopy);
      if (portalDetailsOpen) document.querySelector(".portal-details")?.setAttribute("open", "");
      reinitializeDynamicPage();
    } catch (error) {
      showToast(error.message || "Не удалось обновить страницу", "error");
    }
  };

  const replaceMainFromDocument = (documentCopy) => {
    const nextMain = documentCopy.querySelector("main.container");
    const currentMain = document.querySelector("main.container");
    if (!nextMain || !currentMain) throw new Error("Не удалось обновить страницу");
    currentMain.replaceWith(nextMain);
    document.title = documentCopy.title;
    syncDocumentShell(documentCopy);
    reinitializeDynamicPage();
  };

  let listNavigationInProgress = false;
  const updateListPage = async (url) => {
    if (listNavigationInProgress) return;
    listNavigationInProgress = true;
    const scrollPosition = window.scrollY;
    try {
      const response = await fetch(url, {
        headers: { "X-Requested-With": "Monitoring-Maxval" },
        credentials: "same-origin"
      });
      if (!response.ok) throw new Error("Не удалось обновить список");
      const documentCopy = new DOMParser().parseFromString(await response.text(), "text/html");
      if (new URL(response.url).pathname === "/login") {
        window.location.assign(response.url);
        return;
      }
      replaceMainFromDocument(documentCopy);
      window.history.pushState({}, "", url);
      window.scrollTo({ top: scrollPosition, behavior: "instant" });
    } catch (error) {
      showToast(error.message || "Не удалось обновить список", "error");
    } finally {
      listNavigationInProgress = false;
    }
  };

  const initAutoRefresh = () => {
    if (autoRefreshTimer !== null) window.clearInterval(autoRefreshTimer);
    autoRefreshTimer = null;
    const control = document.querySelector("[data-state-auto-refresh]");
    if (!control) return;
    const storageKey = "monitoring-state-auto-refresh";
    control.checked = localStorage.getItem(storageKey) === "true";
    if (control.checked) autoRefreshTimer = window.setInterval(refreshPageContent, 60000);
    control.addEventListener("change", () => {
      localStorage.setItem(storageKey, control.checked ? "true" : "false");
      initAutoRefresh();
    }, { once: true });
  };


  const closeHelpPopover = () => {
    document.querySelector(".help-popover")?.remove();
    document.querySelectorAll("[data-help][aria-expanded='true'], [data-audit-details][aria-expanded='true']").forEach((item) => item.setAttribute("aria-expanded", "false"));
  };

  const showHelpPopover = (trigger) => {
    const text = trigger.dataset.help || trigger.dataset.auditDetails;
    if (!text) return;
    const wasOpen = trigger.getAttribute("aria-expanded") === "true";
    closeHelpPopover();
    if (wasOpen) return;
    const popover = document.createElement("div");
    popover.className = "help-popover";
    popover.setAttribute("role", "dialog");
    popover.textContent = text;
    document.body.append(popover);
    trigger.setAttribute("aria-expanded", "true");
    const rect = trigger.getBoundingClientRect();
    const margin = 12;
    const width = Math.min(
      trigger.hasAttribute("data-help-wide") ? 560 : trigger.hasAttribute("data-audit-details") ? 440 : 340,
      window.innerWidth - margin * 2
    );
    popover.style.width = `${width}px`;
    let left = rect.left + rect.width / 2 - width / 2;
    left = Math.max(margin, Math.min(left, window.innerWidth - width - margin));
    let top = rect.bottom + 8;
    if (top + popover.offsetHeight > window.innerHeight - margin) {
      top = Math.max(margin, rect.top - popover.offsetHeight - 8);
    }
    popover.style.left = `${left}px`;
    popover.style.top = `${top}px`;
  };

  const initScheduleForms = () => {
    document.querySelectorAll(".schedule-form").forEach((form) => {
      const always = form.querySelector("[data-schedule-24x7]");
      const days = form.querySelector("[data-schedule-days]");
      if (!always || !days || always.dataset.scheduleReady) return;
      always.dataset.scheduleReady = "true";
      const sync = () => {
        days.classList.toggle("is-disabled", always.checked);
        days.querySelectorAll("input").forEach((input) => { input.disabled = always.checked; });
      };
      sync();
      always.addEventListener("change", sync);
    });
  };

  const initChatCompose = () => {
    document.querySelectorAll("[data-chat-compose]").forEach((form) => {
      const textarea = form.querySelector("[data-chat-body]");
      const counter = form.querySelector("[data-chat-counter]");
      const suggestions = form.querySelector("[data-chat-target-suggestions]");
      if (!textarea || !counter || textarea.dataset.composeReady) return;
      textarea.dataset.composeReady = "true";
      let targets = [];
      try {
        const parsed = JSON.parse(form.dataset.chatTargets || "[]");
        targets = Array.isArray(parsed) ? parsed.filter((item) => item && item.id && item.name) : [];
      } catch (_) { /* Suggestions are optional; normal chat input remains available. */ }
      let mentionStart = -1;
      let activeSuggestion = -1;
      const limit = Number(textarea.maxLength > 0 ? textarea.maxLength : 2000);
      const syncCounter = () => {
        const count = textarea.value.length;
        counter.textContent = `${count} / ${limit}`;
        counter.classList.toggle("is-near-limit", count >= Math.floor(limit * 0.9));
        counter.classList.toggle("is-at-limit", count >= limit);
      };
      const closeSuggestions = () => {
        mentionStart = -1;
        activeSuggestion = -1;
        if (suggestions) suggestions.hidden = true;
        textarea.removeAttribute("aria-activedescendant");
      };
      const chooseTarget = (target) => {
        if (!target || mentionStart < 0) return;
        const cursor = textarea.selectionStart;
        const marker = `@${target.name}\u2063${target.id}\u2063`;
        textarea.value = `${textarea.value.slice(0, mentionStart)}${marker} ${textarea.value.slice(cursor)}`;
        const nextCursor = mentionStart + marker.length + 1;
        textarea.setSelectionRange(nextCursor, nextCursor);
        syncCounter();
        closeSuggestions();
        textarea.focus();
      };
      const renderSuggestions = () => {
        if (!suggestions || !targets.length) return;
        const cursor = textarea.selectionStart;
        const before = textarea.value.slice(0, cursor);
        const at = before.lastIndexOf("@");
        const validStart = at >= 0 && (at === 0 || /[\s([{-]/.test(before[at - 1]));
        const query = validStart ? before.slice(at + 1) : "";
        if (!validStart || /[\u2063\r\n]/.test(query)) {
          closeSuggestions();
          return;
        }
        const normalized = query.trim().toLocaleLowerCase("ru-RU");
        const matches = targets.filter((target) => (
          target.name.toLocaleLowerCase("ru-RU").includes(normalized)
          || String(target.site_name || "").toLocaleLowerCase("ru-RU").includes(normalized)
        ));
        if (!matches.length) {
          closeSuggestions();
          return;
        }
        mentionStart = at;
        activeSuggestion = Math.min(Math.max(activeSuggestion, 0), matches.length - 1);
        suggestions.replaceChildren(...matches.map((target, index) => {
          const option = document.createElement("button");
          option.type = "button";
          option.className = "chat-target-suggestion";
          option.id = `chat-target-suggestion-${index}`;
          option.setAttribute("role", "option");
          option.setAttribute("aria-selected", String(index === activeSuggestion));
          option.innerHTML = `<strong></strong><small></small>`;
          option.querySelector("strong").textContent = target.name;
          option.querySelector("small").textContent = target.site_name || "Объект";
          option.addEventListener("mousedown", (event) => {
            event.preventDefault();
            chooseTarget(target);
          });
          return option;
        }));
        textarea.setAttribute("aria-activedescendant", `chat-target-suggestion-${activeSuggestion}`);
        suggestions.hidden = false;
      };
      syncCounter();
      textarea.addEventListener("input", () => { syncCounter(); renderSuggestions(); });
      textarea.addEventListener("click", renderSuggestions);
      textarea.addEventListener("keydown", (event) => {
        const options = suggestions && !suggestions.hidden
          ? [...suggestions.querySelectorAll(".chat-target-suggestion")]
          : [];
        if (options.length && (event.key === "ArrowDown" || event.key === "ArrowUp")) {
          event.preventDefault();
          activeSuggestion = (activeSuggestion + (event.key === "ArrowDown" ? 1 : -1) + options.length) % options.length;
          renderSuggestions();
          return;
        }
        if (options.length && event.key === "Escape") {
          event.preventDefault();
          closeSuggestions();
          return;
        }
        if (options.length && event.key === "Enter" && !event.shiftKey && !event.isComposing) {
          event.preventDefault();
          options[activeSuggestion]?.dispatchEvent(new MouseEvent("mousedown", { bubbles: true, cancelable: true }));
          return;
        }
        if (event.key !== "Enter" || event.shiftKey || event.isComposing) return;
        event.preventDefault();
        if (!textarea.value.trim()) return;
        form.requestSubmit();
      });
      textarea.addEventListener("blur", () => window.setTimeout(closeSuggestions, 120));
    });
  };

  const formatChartNumber = (value) => {
    const digits = Math.abs(value) >= 100 || Number.isInteger(value) ? 0 : 1;
    return new Intl.NumberFormat("ru-RU", {
      minimumFractionDigits: 0,
      maximumFractionDigits: digits
    }).format(value);
  };

  const formatChartTime = (raw, compact = false) => {
    const value = new Date(raw);
    if (Number.isNaN(value.getTime())) return "—";
    return new Intl.DateTimeFormat("ru-RU", compact
      ? { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" }
      : { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit" }
    ).format(value);
  };

  const initStandardCharts = () => {
    document.querySelectorAll("[data-chart]").forEach((chart) => {
      if (chart.dataset.chartReady) return;
      chart.dataset.chartReady = "true";
      let times;
      let series;
      try {
        times = JSON.parse(chart.dataset.chartTimes || "[]");
        series = JSON.parse(chart.dataset.chartSeries || "[]");
      } catch (_) {
        return;
      }
      const maximum = Number(chart.dataset.chartMax || "1") || 1;
      const unit = chart.dataset.chartUnit || "";
      const yAxis = chart.querySelector(".chart-y-axis");
      const grid = chart.querySelector(".chart-grid");
      const xAxis = chart.querySelector(".chart-x-axis");
      const svg = chart.querySelector(".chart-svg");
      const cursor = chart.querySelector(".chart-cursor");
      const tooltip = chart.querySelector(".chart-tooltip");
      if (!yAxis || !grid || !xAxis || !svg || !cursor || !tooltip || !series.length) return;

      for (let step = 0; step <= 4; step += 1) {
        const value = maximum * (4 - step) / 4;
        const label = document.createElement("span");
        label.textContent = formatChartNumber(value);
        yAxis.append(label);
        const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
        const coordinate = (74 * step / 4).toFixed(1);
        line.setAttribute("x1", "0");
        line.setAttribute("x2", "320");
        line.setAttribute("y1", coordinate);
        line.setAttribute("y2", coordinate);
        grid.append(line);
      }
      const indices = [0, Math.floor(Math.max(0, times.length - 1) / 2), Math.max(0, times.length - 1)];
      xAxis.querySelectorAll("span").forEach((label, index) => {
        label.textContent = times[indices[index]] ? formatChartTime(times[indices[index]], true) : "—";
      });

      const showTooltip = (event) => {
        document.querySelectorAll("[data-chart]").forEach((otherChart) => {
          if (otherChart === chart) return;
          otherChart.querySelector(".chart-tooltip")?.setAttribute("hidden", "");
          const otherCursor = otherChart.querySelector(".chart-cursor");
          otherCursor?.setAttribute("hidden", "");
          if (otherCursor) otherCursor.style.display = "none";
        });
        const length = Math.max(...series.map((item) => item.values?.length || 0));
        if (!length) return;
        const rect = svg.getBoundingClientRect();
        const ratio = Math.min(1, Math.max(0, (event.clientX - rect.left) / rect.width));
        const index = Math.min(length - 1, Math.round(ratio * (length - 1)));
        const x = (320 * index / Math.max(1, length - 1)).toFixed(1);
        cursor.setAttribute("x1", x);
        cursor.setAttribute("x2", x);
        cursor.removeAttribute("hidden");
        cursor.style.display = "block";
        tooltip.replaceChildren();
        const time = document.createElement("strong");
        time.textContent = times[index] ? formatChartTime(times[index]) : "Нет времени";
        tooltip.append(time);
        series.forEach((item) => {
          const row = document.createElement("span");
          const value = Number(item.values?.[index] ?? 0);
          row.textContent = `${item.label}: ${formatChartNumber(value)}${unit ? ` ${unit}` : ""}`;
          tooltip.append(row);
        });
        tooltip.hidden = false;
        const margin = 12;
        const left = Math.min(window.innerWidth - tooltip.offsetWidth - margin, event.clientX + 14);
        const top = Math.min(window.innerHeight - tooltip.offsetHeight - margin, event.clientY + 14);
        tooltip.style.left = `${Math.max(margin, left)}px`;
        tooltip.style.top = `${Math.max(margin, top)}px`;
      };
      const hideTooltip = () => {
        cursor.setAttribute("hidden", "");
        cursor.style.display = "none";
        tooltip.setAttribute("hidden", "");
      };
      svg.style.pointerEvents = "all";
      svg.addEventListener("pointermove", showTooltip);
      svg.addEventListener("pointerdown", showTooltip);
      svg.addEventListener("pointerleave", hideTooltip);
    });
  };

  const centerActiveNavigationItem = () => {
    if (!window.matchMedia("(max-width: 1050px)").matches) return;
    const nav = document.querySelector(".topbar nav");
    const active = nav?.querySelector('.nav-link[aria-current="page"]');
    if (!nav || !active || nav.scrollWidth <= nav.clientWidth) return;

    const navRect = nav.getBoundingClientRect();
    const activeRect = active.getBoundingClientRect();
    const offset = activeRect.left + activeRect.width / 2 - (navRect.left + navRect.width / 2);
    nav.scrollLeft = Math.max(0, Math.min(nav.scrollWidth - nav.clientWidth, nav.scrollLeft + offset));
  };

  const initPage = () => {
    initTargetForms();
    initScheduleForms();
    initChatCompose();
    initStandardCharts();
    document.querySelectorAll("select[data-auto-submit]").forEach((select) => {
      if (select.dataset.submitReady) return;
      select.dataset.submitReady = "true";
      select.addEventListener("change", () => select.form?.requestSubmit());
    });
    initAutoRefresh();
    centerActiveNavigationItem();
  };

  document.addEventListener("click", (event) => {
    const help = event.target.closest("[data-help], [data-audit-details]");
    if (help) {
      event.preventDefault();
      event.stopPropagation();
      showHelpPopover(help);
      return;
    }
    if (!event.target.closest(".help-popover")) closeHelpPopover();

    const timezoneButton = event.target.closest("[data-detect-timezone]");
    if (timezoneButton) {
      event.preventDefault();
      const form = timezoneButton.closest("form");
      const input = form?.querySelector("[data-timezone-input]");
      try {
        const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
        if (!input || !timezone) throw new Error("Браузер не сообщил часовой пояс");
        input.value = timezone;
        input.dispatchEvent(new Event("input", { bubbles: true }));
        showToast(`Определён часовой пояс: ${timezone}. Нажмите «Сохранить».`);
      } catch (error) {
        showToast(error.message || "Не удалось определить часовой пояс автоматически", "error");
      }
      return;
    }

    const button = event.target.closest("[data-theme-toggle]");
    if (!button) return;
    const current = root.dataset.theme;
    const next = current === "dark" ? "light" : "dark";
    root.dataset.theme = next;
    localStorage.setItem("monitoring-theme", next);
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeHelpPopover();
  });

  document.addEventListener("click", (event) => {
    const button = event.target.closest?.("[data-table-editor-toggle]");
    if (!button) return;
    event.preventDefault();
    const editor = document.getElementById(button.dataset.tableEditorToggle);
    if (!editor) return;
    document.querySelectorAll("details.table-editor[open]").forEach((item) => {
      if (item !== editor && !item.contains(editor)) {
        item.removeAttribute("open");
        document.querySelector(`[data-table-editor-toggle="${item.id}"]`)
          ?.setAttribute("aria-expanded", "false");
      }
    });
    editor.open = !editor.open;
    button.setAttribute("aria-expanded", String(editor.open));
  });
  window.addEventListener("resize", closeHelpPopover, { passive: true });
  window.addEventListener("scroll", closeHelpPopover, { passive: true });

  document.addEventListener("keydown", (event) => {
    const row = event.target.closest?.("[data-audit-details]");
    if (!row) return;
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      showHelpPopover(row);
    }
    if (event.key === "Escape") closeHelpPopover();
  });

  document.addEventListener("submit", async (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    if (form.dataset.confirm && !window.confirm(form.dataset.confirm)) {
      event.preventDefault();
      return;
    }
    const action = new URL(form.action, window.location.href);
    const asyncAllowed = form.method.toLowerCase() === "post"
      && action.origin === window.location.origin
      && action.pathname !== "/login"
      && action.pathname !== "/logout"
      && !form.hasAttribute("data-no-async");
    if (!asyncAllowed) return;

    event.preventDefault();
    const submitter = event.submitter;
    const scrollPosition = window.scrollY;
    const openEditorAction = form.closest("details[open]")?.querySelector("form")?.action;
    if (submitter) submitter.disabled = true;
    form.setAttribute("aria-busy", "true");
    try {
      const response = await fetch(action, {
        method: "POST",
        body: new FormData(form),
        credentials: "same-origin",
        headers: { "X-Requested-With": "Monitoring-Maxval" }
      });
      const contentType = response.headers.get("content-type") || "";
      if (!response.ok && contentType.includes("application/json")) {
        const payload = await response.json();
        throw new Error(errorMessage(payload.detail, "Операция не выполнена"));
      }
      const documentCopy = new DOMParser().parseFromString(await response.text(), "text/html");
      if (new URL(response.url).pathname === "/login") {
        window.location.assign(response.url);
        return;
      }
      const nextMain = documentCopy.querySelector("main.container");
      const currentMain = document.querySelector("main.container");
      if (!nextMain || !currentMain) throw new Error("Сервер вернул неожиданный ответ");
      const success = nextMain.querySelector(".alert-success")?.textContent?.trim();
      const failure = nextMain.querySelector(".alert-error")?.textContent?.trim();
      nextMain.querySelectorAll(".alert").forEach((alert) => alert.remove());
      const previousPath = window.location.pathname;
      currentMain.replaceWith(nextMain);
      document.title = documentCopy.title;
      syncDocumentShell(documentCopy);
      const cleanUrl = new URL(response.url);
      const renderedPagePath = response.headers.get("X-Monitoring-Page-Path");
      if (renderedPagePath?.startsWith("/")) cleanUrl.pathname = renderedPagePath;
      cleanUrl.searchParams.delete("notice");
      cleanUrl.searchParams.delete("error");
      window.history.replaceState({}, "", cleanUrl);
      reinitializeDynamicPage();
      if (openEditorAction) {
        const reopenedForm = [...document.querySelectorAll("details form")]
          .find((item) => item.action === openEditorAction);
        if (reopenedForm) reopenedForm.closest("details").open = true;
      }
      window.scrollTo({ top: cleanUrl.pathname === previousPath ? scrollPosition : 0, behavior: "instant" });
      showToast(failure || success || "Изменения сохранены", failure ? "error" : "success");
    } catch (error) {
      showToast(error.message || "Не удалось выполнить операцию", "error");
    } finally {
      if (submitter) submitter.disabled = false;
      form.removeAttribute("aria-busy");
    }
  });

  document.addEventListener("click", (event) => {
    const link = event.target.closest?.(".sort-link, .pagination a.page-button");
    if (!link || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    const url = new URL(link.href, window.location.href);
    if (url.origin !== window.location.origin) return;
    event.preventDefault();
    updateListPage(url);
  });

  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement) || !form.matches(".page-size-form")) return;
    event.preventDefault();
    const url = new URL(form.action || window.location.href, window.location.href);
    const parameters = new URLSearchParams();
    new FormData(form).forEach((value, key) => {
      if (typeof value === "string") parameters.append(key, value);
    });
    url.search = parameters.toString();
    updateListPage(url);
  });

  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement) || !form.matches("[data-snmp-history-selector]")) return;
    const selection = form.elements.namedItem("snmp_graph");
    if (!(selection instanceof HTMLSelectElement)) return;
    event.preventDefault();
    const url = new URL(window.location.href);
    url.searchParams.set("snmp_graph", selection.value);
    url.searchParams.delete("notice");
    url.searchParams.delete("error");
    updateListPage(url);
  });


  let communicationStatusTimer = null;
  let chatPollingTimer = null;
  let chatFullscreenActive = window.sessionStorage.getItem("monitoring-chat-fullscreen") === "true";
  let chatFullscreenScrollY = 0;

  const setCounterBadge = (selector, value) => {
    const badges = document.querySelectorAll(selector);
    if (!badges.length) return;
    const count = Number(value || 0);
    badges.forEach((badge) => {
      badge.textContent = count > 99 ? "99+" : String(count);
      badge.hidden = count <= 0;
    });
  };

  const refreshCommunicationStatus = async () => {
    if (!document.querySelector(".communication-dock")) return;
    try {
      const response = await fetch("/api/communication/status", {
        credentials: "same-origin",
        headers: { "Accept": "application/json" },
        cache: "no-store"
      });
      if (!response.ok) return;
      const payload = await response.json();
      setCounterBadge("[data-chat-badge], [data-chat-drawer-badge]", payload.chat_unread);
      setCounterBadge("[data-notification-badge]", payload.notifications_unread);
      const total = Math.max(Number(payload.chat_unread || 0), Number(payload.notifications_unread || 0));
      if ("setAppBadge" in navigator) {
        if (total > 0) navigator.setAppBadge(total).catch(() => {});
        else if ("clearAppBadge" in navigator) navigator.clearAppBadge().catch(() => {});
      }
    } catch (_error) {
      // Connection loss must not interrupt the interface.
    }
  };

  const initCommunicationStatus = () => {
    if (communicationStatusTimer) window.clearInterval(communicationStatusTimer);
    communicationStatusTimer = null;
    if (!document.querySelector(".communication-dock")) return;
    refreshCommunicationStatus();
    communicationStatusTimer = window.setInterval(refreshCommunicationStatus, 15000);
  };

  const chatMessageNode = (item) => {
    const article = document.createElement("article");
    article.className = `chat-message ${item.own ? "is-own" : "is-other"}`;
    article.dataset.messageId = String(item.id);
    const meta = document.createElement("div");
    meta.className = "chat-message-meta";
    const author = document.createElement("strong");
    author.textContent = item.sender_name;
    const timeActions = document.createElement("span");
    const time = document.createElement("time");
    time.textContent = item.created_at;
    timeActions.append(time);
    if (item.own) {
      const edit = document.createElement("button");
      edit.className = "chat-message-edit-button";
      edit.type = "button";
      edit.dataset.chatEditToggle = "";
      edit.setAttribute("aria-expanded", "false");
      edit.title = "Изменить сообщение";
      edit.setAttribute("aria-label", "Изменить сообщение");
      edit.textContent = "✎";
      timeActions.append(edit);
    }
    meta.append(author, timeActions);
    const body = document.createElement("p");
    const parts = Array.isArray(item.body_parts) ? item.body_parts : [{ text: item.body || "" }];
    parts.forEach((part) => {
      const text = typeof part?.text === "string" ? part.text : "";
      const targetId = Number(part?.target_id);
      if (Number.isInteger(targetId) && targetId > 0) {
        const link = document.createElement("a");
        link.className = "chat-target-mention";
        link.href = `/?focus_target_id=${encodeURIComponent(targetId)}`;
        link.title = "Открыть объект на странице состояния";
        link.textContent = text;
        body.append(link);
      } else body.append(document.createTextNode(text));
    });
    article.append(meta, body);
    if (item.own) {
      const peerId = document.querySelector("[data-chat-conversation][data-peer-id]")?.dataset.peerId;
      const csrfToken = document.querySelector("meta[name='csrf-token']")?.content;
      if (peerId && csrfToken) {
        const editor = document.createElement("form");
        editor.className = "chat-message-editor";
        editor.method = "post";
        editor.action = `/chat/messages/${encodeURIComponent(item.id)}/edit`;
        editor.hidden = true;
        editor.innerHTML = `<input type="hidden" name="csrf_token" value="${csrfToken}"><input type="hidden" name="recipient_id" value="${peerId}"><textarea name="body" rows="2" maxlength="2000" required></textarea><span><button class="button button-secondary" type="button" data-chat-edit-cancel>Отмена</button><button class="button" type="submit">Сохранить</button></span>`;
        editor.querySelector("textarea").value = item.body;
        article.append(editor);
      }
      const state = document.createElement("small");
      state.dataset.chatReadState = item.read ? "read" : "delivered";
      state.textContent = item.read ? "Прочитано" : "Доставлено";
      article.append(state);
    }
    if (item.edited) {
      const edited = document.createElement("small");
      edited.className = "chat-message-edited";
      edited.textContent = "Изменено";
      article.append(edited);
    }
    return article;
  };

  const loadOlderChatMessages = async (messages) => {
    if (!messages || messages.dataset.loading === "true" || messages.dataset.hasMore !== "true") return;
    const peerId = document.querySelector("[data-chat-conversation][data-peer-id]")?.dataset.peerId;
    const first = messages.querySelector(".chat-message[data-message-id]");
    if (!peerId || !first) return;
    messages.dataset.loading = "true";
    const previousHeight = messages.scrollHeight;
    try {
      const response = await fetch(`/api/chat/${encodeURIComponent(peerId)}/messages?before_id=${encodeURIComponent(first.dataset.messageId)}`, {
        credentials: "same-origin",
        headers: { "Accept": "application/json" },
        cache: "no-store"
      });
      if (!response.ok) return;
      const payload = await response.json();
      const anchor = messages.querySelector(".chat-history-loader")?.nextSibling || first;
      for (const item of payload.messages || []) messages.insertBefore(chatMessageNode(item), anchor);
      messages.dataset.hasMore = payload.has_more ? "true" : "false";
      const loader = messages.querySelector("[data-chat-history-loader]");
      if (loader) loader.hidden = !payload.has_more;
      messages.scrollTop += messages.scrollHeight - previousHeight;
    } catch (_error) {
      // The next upward scroll retries the history request.
    } finally {
      messages.dataset.loading = "false";
    }
  };

  const refreshOpenChat = async () => {
    const conversation = document.querySelector("[data-chat-conversation][data-peer-id]");
    const peerId = conversation?.dataset.peerId;
    if (!peerId) return;
    const currentMessages = document.querySelector("[data-chat-messages]");
    if (!currentMessages) return;
    const wasNearBottom = currentMessages.scrollHeight - currentMessages.scrollTop - currentMessages.clientHeight < 90;
    const currentIds = new Set([...currentMessages.querySelectorAll(".chat-message[data-message-id]")].map((node) => node.dataset.messageId));
    try {
      const response = await fetch(`/chat?user_id=${encodeURIComponent(peerId)}`, {
        credentials: "same-origin",
        headers: { "X-Requested-With": "Monitoring-Maxval-Poll" },
        cache: "no-store"
      });
      if (!response.ok) return;
      const copy = new DOMParser().parseFromString(await response.text(), "text/html");
      const incomingArea = copy.querySelector("[data-chat-messages]");
      let appended = 0;
      if (incomingArea) {
        const insertionPoint = currentMessages.querySelector(".chat-system-request, [data-chat-new-messages]");
        for (const node of incomingArea.querySelectorAll(".chat-message[data-message-id]")) {
          if (currentIds.has(node.dataset.messageId)) {
            const currentNode = currentMessages.querySelector(`.chat-message[data-message-id="${node.dataset.messageId}"]`);
            const incomingState = node.querySelector("[data-chat-read-state]");
            const currentState = currentNode?.querySelector("[data-chat-read-state]");
            if (incomingState && currentState && incomingState.dataset.chatReadState !== currentState.dataset.chatReadState) {
              currentState.dataset.chatReadState = incomingState.dataset.chatReadState || "delivered";
              currentState.textContent = incomingState.textContent || "Доставлено";
            }
            const incomingBody = node.querySelector("p")?.textContent;
            const currentBody = currentNode?.querySelector("p")?.textContent;
            const incomingEdited = Boolean(node.querySelector(".chat-message-edited"));
            const currentEdited = Boolean(currentNode?.querySelector(".chat-message-edited"));
            if (currentNode && (incomingBody !== currentBody || incomingEdited !== currentEdited)) {
              currentNode.replaceWith(document.importNode(node, true));
            }
            continue;
          }
          currentMessages.insertBefore(document.importNode(node, true), insertionPoint || null);
          appended += 1;
        }
        // Refresh deletion-request/status cards without touching already loaded history.
        currentMessages.querySelectorAll(".chat-system-request, .chat-deletion-status").forEach((node) => node.remove());
        const loader = currentMessages.querySelector("[data-chat-history-loader]");
        const topAnchor = loader?.nextSibling || currentMessages.firstChild;
        for (const node of [...incomingArea.querySelectorAll(".chat-history-boundary")].reverse()) {
          currentMessages.insertBefore(document.importNode(node, true), topAnchor || null);
        }
        const newButton = currentMessages.querySelector("[data-chat-new-messages]");
        for (const node of incomingArea.querySelectorAll(".chat-system-request")) {
          currentMessages.insertBefore(document.importNode(node, true), newButton || null);
        }
      }
      const newContacts = copy.querySelector(".chat-contact-list");
      const currentContacts = document.querySelector(".chat-contact-list");
      if (newContacts && currentContacts && newContacts.innerHTML !== currentContacts.innerHTML) currentContacts.innerHTML = newContacts.innerHTML;

      // Presence in the open-dialog heading must follow normal session activity,
      // not wait for a form submit/full-page redirect after sending a message.
      const incomingPeerPresence = copy.querySelector("[data-chat-peer-presence]");
      const currentPeerPresence = document.querySelector("[data-chat-peer-presence]");
      if (incomingPeerPresence && currentPeerPresence) {
        const isDeleted = incomingPeerPresence.classList.contains("is-deleted");
        const isOnline = !isDeleted && incomingPeerPresence.classList.contains("is-online");
        currentPeerPresence.classList.toggle("is-deleted", isDeleted);
        currentPeerPresence.classList.toggle("is-online", isOnline);
        currentPeerPresence.classList.toggle("is-offline", !isDeleted && !isOnline);
        const stateLabel = isDeleted ? "Удалён" : (isOnline ? "Онлайн" : "Оффлайн");
        currentPeerPresence.setAttribute("title", stateLabel);
        currentPeerPresence.setAttribute("aria-label", stateLabel);
      }

      const newMessagesButton = currentMessages.querySelector("[data-chat-new-messages]");
      if (appended && wasNearBottom) {
        currentMessages.scrollTop = currentMessages.scrollHeight;
        if (newMessagesButton) newMessagesButton.hidden = true;
      } else if (appended && newMessagesButton) {
        newMessagesButton.hidden = false;
      }
      refreshCommunicationStatus();
    } catch (_error) {
      // Silent retry on the next interval.
    }
  };

  const initChatPolling = () => {
    if (chatPollingTimer) window.clearInterval(chatPollingTimer);
    chatPollingTimer = null;
    const messages = document.querySelector("[data-chat-messages]");
    if (messages) {
      const scrollToLatest = () => { messages.scrollTop = messages.scrollHeight; };
      scrollToLatest();
      requestAnimationFrame(() => { scrollToLatest(); requestAnimationFrame(scrollToLatest); });
      messages.addEventListener("scroll", () => {
        if (messages.scrollTop < 80) loadOlderChatMessages(messages);
        const button = messages.querySelector("[data-chat-new-messages]");
        if (button && messages.scrollHeight - messages.scrollTop - messages.clientHeight < 90) button.hidden = true;
      }, { passive: true });
      messages.querySelector("[data-chat-new-messages]")?.addEventListener("click", () => {
        messages.scrollTo({ top: messages.scrollHeight, behavior: "smooth" });
      });
      messages.addEventListener("click", (event) => {
        const toggle = event.target.closest?.("[data-chat-edit-toggle]");
        const cancel = event.target.closest?.("[data-chat-edit-cancel]");
        if (!toggle && !cancel) return;
        event.preventDefault();
        const message = (toggle || cancel).closest(".chat-message");
        const editor = message?.querySelector(".chat-message-editor");
        const editButton = message?.querySelector("[data-chat-edit-toggle]");
        if (!editor) return;
        const open = toggle ? editor.hidden : false;
        editor.hidden = !open;
        editButton?.setAttribute("aria-expanded", String(open));
        if (open) editor.querySelector("textarea")?.focus();
      });
    }
    const conversation = document.querySelector("[data-chat-conversation][data-peer-id]");
    const peerId = conversation?.dataset.peerId;
    if (!peerId) return;
    const refreshVisiblePresence = () => {
      if (document.visibilityState !== "visible") return;
      fetch(`/api/chat/${encodeURIComponent(peerId)}/presence`, {
        method: "POST", credentials: "same-origin", cache: "no-store"
      }).catch(() => {});
    };
    refreshVisiblePresence();
    document.addEventListener("visibilitychange", refreshVisiblePresence, { once: true });
    chatPollingTimer = window.setInterval(refreshOpenChat, 5000);
    window.setInterval(refreshVisiblePresence, 30000);
  };

  const setChatDrawerOpen = (open) => {
    const drawer = document.querySelector("[data-chat-contacts-drawer]");
    const backdrop = document.querySelector("[data-chat-drawer-backdrop]");
    const toggle = document.querySelector("[data-chat-dialogs-toggle]");
    if (!drawer) return;
    drawer.classList.toggle("is-open", open);
    if (backdrop) backdrop.hidden = !open;
    if (toggle) toggle.setAttribute("aria-expanded", open ? "true" : "false");
    document.body.classList.toggle("chat-drawer-open", open);
  };

  const initChatDrawer = () => {
    const drawer = document.querySelector("[data-chat-contacts-drawer]");
    const toggle = document.querySelector("[data-chat-dialogs-toggle]");
    const backdrop = document.querySelector("[data-chat-drawer-backdrop]");
    if (!drawer || !toggle) {
      document.body.classList.remove("chat-drawer-open");
      return;
    }
    if (!toggle.dataset.drawerReady) {
      toggle.dataset.drawerReady = "true";
      toggle.addEventListener("click", () => setChatDrawerOpen(!drawer.classList.contains("is-open")));
    }
    if (backdrop && !backdrop.dataset.drawerReady) {
      backdrop.dataset.drawerReady = "true";
      backdrop.addEventListener("click", () => setChatDrawerOpen(false));
    }
    drawer.querySelectorAll(".chat-contact").forEach((link) => {
      if (link.dataset.drawerReady) return;
      link.dataset.drawerReady = "true";
      link.addEventListener("click", () => setChatDrawerOpen(false));
    });
  };

  const applyChatFullscreen = () => {
    const isChatPage = document.body.classList.contains("chat-page") && Boolean(document.querySelector(".chat-layout"));
    document.body.classList.toggle("chat-fullscreen", chatFullscreenActive && isChatPage);
    document.querySelectorAll("[data-chat-fullscreen-toggle]").forEach((toggle) => {
      toggle.setAttribute("aria-pressed", chatFullscreenActive ? "true" : "false");
      toggle.setAttribute("title", chatFullscreenActive ? "Свернуть чат" : "Развернуть чат на весь экран");
      toggle.setAttribute("aria-label", chatFullscreenActive ? "Свернуть чат" : "Развернуть чат на весь экран");
    });
  };

  const initChatFullscreen = () => {
    const toggles = [...document.querySelectorAll("[data-chat-fullscreen-toggle]")];
    if (!toggles.length) {
      if (!document.body.classList.contains("chat-page")) {
        chatFullscreenActive = false;
        window.sessionStorage.removeItem("monitoring-chat-fullscreen");
      }
      document.body.classList.remove("chat-fullscreen");
      return;
    }
    applyChatFullscreen();
    toggles.forEach((toggle) => {
      if (toggle.dataset.fullscreenReady) return;
      toggle.dataset.fullscreenReady = "true";
      toggle.addEventListener("click", () => {
        if (!chatFullscreenActive) chatFullscreenScrollY = window.scrollY;
        chatFullscreenActive = !chatFullscreenActive;
        if (chatFullscreenActive) window.sessionStorage.setItem("monitoring-chat-fullscreen", "true");
        else window.sessionStorage.removeItem("monitoring-chat-fullscreen");
        applyChatFullscreen();
        if (!chatFullscreenActive) requestAnimationFrame(() => window.scrollTo({ top: chatFullscreenScrollY, behavior: "instant" }));
      });
    });
  };

  const focusNavigationTarget = () => {
    const params = new URLSearchParams(window.location.search);
    let rawId = window.location.hash ? decodeURIComponent(window.location.hash.slice(1)) : "";
    if (!rawId && window.location.pathname === "/incidents" && params.get("focus_id")) rawId = `incident-${params.get("focus_id")}`;
    if (!rawId && window.location.pathname === "/" && params.get("focus_target_id")) rawId = `target-${params.get("focus_target_id")}`;
    if (!rawId && window.location.pathname === "/targets" && params.get("focus_target_id")) rawId = `target-${params.get("focus_target_id")}-editor`;
    const target = rawId ? document.getElementById(rawId) : null;
    if (!target) return;
    if (target.matches("details.table-editor")) {
      target.open = true;
      document.querySelector(`[data-table-editor-toggle="${target.id}"]`)
        ?.setAttribute("aria-expanded", "true");
    }
    target.classList.add("is-navigation-focus");
    target.scrollIntoView({ behavior: "smooth", block: "center" });
    window.setTimeout(() => target.classList.remove("is-navigation-focus"), 3200);
  };

  document.addEventListener("click", (event) => {
    const link = event.target.closest?.("[data-navigation-focus]");
    if (!link) return;
    const target = document.getElementById(link.dataset.navigationFocus);
    if (!target) return;
    target.classList.add("is-navigation-focus");
    window.setTimeout(() => target.classList.remove("is-navigation-focus"), 3200);
  });

  const csrfHeaderToken = () => document.querySelector('meta[name="csrf-token"]')?.content || "";

  const urlBase64ToUint8Array = (value) => {
    const padding = "=".repeat((4 - value.length % 4) % 4);
    const base64 = (value + padding).replace(/-/g, "+").replace(/_/g, "/");
    const raw = window.atob(base64);
    return Uint8Array.from([...raw].map((char) => char.charCodeAt(0)));
  };

  const pushSupported = () => (
    window.isSecureContext
    && "serviceWorker" in navigator
    && "PushManager" in window
    && "Notification" in window
  );

  let pushSubscriptionSynced = false;

  const pushSubscriptionPayload = (subscription) => {
    const json = subscription.toJSON();
    return { endpoint: subscription.endpoint, keys: json.keys || {} };
  };

  const showPushResubscribeNotice = () => {
    const storageKey = "monitoring-push-resubscribe-notice";
    if (sessionStorage.getItem(storageKey)) return;
    sessionStorage.setItem(storageKey, "true");
    showToast("Push на этом устройстве требует повторного подключения", "error");
  };

  const syncCurrentPushSubscription = async () => {
    if (pushSubscriptionSynced || !pushSupported() || !csrfHeaderToken()) return;
    pushSubscriptionSynced = true;
    try {
      const registration = await navigator.serviceWorker.ready;
      const subscription = await registration.pushManager.getSubscription();
      if (!subscription) {
        if (Notification.permission === "granted") showPushResubscribeNotice();
        return;
      }
      const response = await fetch("/push/subscribe", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfHeaderToken() },
        body: JSON.stringify(pushSubscriptionPayload(subscription))
      });
      if (!response.ok) throw new Error("Не удалось синхронизировать Push-подписку");
    } catch (error) {
      console.warn(error.message || "Push-подписка не синхронизирована");
    }
  };

  const syncPushState = async () => {
    const state = document.querySelector("[data-push-state]");
    if (!state) return;
    const enable = document.querySelector("[data-push-enable]");
    const disable = document.querySelector("[data-push-disable]");
    if (!pushSupported()) {
      state.textContent = window.isSecureContext
        ? "Push не поддерживается этим браузером"
        : "Push доступен только через HTTPS";
      if (enable) enable.hidden = true;
      if (disable) disable.hidden = true;
      return;
    }
    try {
      const registration = await navigator.serviceWorker.ready;
      const subscription = await registration.pushManager.getSubscription();
      if (subscription) {
        state.textContent = "Push включён на этом устройстве";
        if (enable) enable.hidden = true;
        if (disable) disable.hidden = false;
      } else {
        state.textContent = Notification.permission === "denied"
          ? "Push запрещён в настройках браузера"
          : Notification.permission === "granted"
            ? "Push требует повторного подключения на этом устройстве"
            : "Push выключен на этом устройстве";
        if (Notification.permission === "granted") showPushResubscribeNotice();
        if (enable) enable.hidden = Notification.permission === "denied";
        if (disable) disable.hidden = true;
      }
    } catch (_error) {
      state.textContent = "Не удалось определить состояние Push";
    }
  };

  // Critical remains a Target Health state. This small presentation controller is
  // deliberately shared by the TV wallboard and the ordinary state page: it only
  // reads rendered markers and never creates or changes incidents.
  const initCriticalAlerts = () => {
    const criticalAlert = document.querySelector("[data-critical-alert]");
    if (!criticalAlert) return null;
    if (criticalAlert.dataset.ready) return criticalAlert._criticalAlerts || null;
    criticalAlert.dataset.ready = "true";
    const criticalGrid = criticalAlert.querySelector("[data-critical-alert-grid]");
    const criticalSeenKey = criticalAlert.dataset.criticalStorageKey || "monitoring-critical-alerted";
    const criticalSource = criticalAlert.dataset.criticalSource || "/wallboard";
    let criticalTimer = null;
    let seenCriticalIds = new Set();
    try {
      const stored = JSON.parse(sessionStorage.getItem(criticalSeenKey) || "[]");
      if (Array.isArray(stored)) seenCriticalIds = new Set(stored.map(String));
    } catch (_) { /* Unavailable storage only affects repeated visual cards. */ }
    const criticalTargetsFrom = (root) => [...root.querySelectorAll("[data-critical-target]")]
      .map((node) => ({
        id: String(node.dataset.targetId || ""),
        name: node.dataset.targetName || "Объект",
        description: node.dataset.targetDescription || "Без описания ошибки",
      }))
      .filter((item) => item.id);
    const saveSeenCritical = (items) => {
      seenCriticalIds = new Set(items.map((item) => item.id));
      try { sessionStorage.setItem(criticalSeenKey, JSON.stringify([...seenCriticalIds])); }
      catch (_) { /* The visual state stays active for this page. */ }
    };
    const close = () => {
      if (criticalTimer) window.clearTimeout(criticalTimer);
      criticalTimer = null;
      criticalAlert.hidden = true;
    };
    const show = (items) => {
      if (!criticalGrid || !items.length) return;
      if (criticalTimer) window.clearTimeout(criticalTimer);
      const cardWidth = Math.min(680, Math.max(280, window.innerWidth - 48));
      const cardHeight = Math.min(350, Math.max(250, window.innerHeight - 48));
      const baseLeft = Math.max(24, (window.innerWidth - cardWidth) / 2);
      const baseTop = Math.max(24, (window.innerHeight - cardHeight) / 2);
      const stepX = Math.max(18, Math.min(42, (window.innerWidth - cardWidth - 48) / Math.max(items.length, 1)));
      const stepY = Math.max(14, Math.min(30, (window.innerHeight - cardHeight - 48) / Math.max(items.length, 1)));
      const cascadeCentre = (items.length - 1) / 2;
      const cards = items.map((item, index) => {
        const card = document.createElement("section");
        const closeButton = document.createElement("button");
        const symbol = document.createElement("div");
        const kicker = document.createElement("p");
        const title = document.createElement("h2");
        const name = document.createElement("h3");
        const description = document.createElement("p");
        card.className = "wallboard-critical-alert-card";
        card.style.width = `${cardWidth}px`;
        card.style.minHeight = `${cardHeight}px`;
        card.style.left = `${Math.max(24, Math.min(window.innerWidth - cardWidth - 24, baseLeft + stepX * (index - cascadeCentre)))}px`;
        card.style.top = `${Math.max(24, Math.min(window.innerHeight - cardHeight - 24, baseTop + stepY * (index - cascadeCentre)))}px`;
        card.style.zIndex = String(index + 1);
        card.style.setProperty("--critical-alert-delay", `${index * 140}ms`);
        closeButton.type = "button";
        closeButton.className = "wallboard-critical-alert-card-close";
        closeButton.setAttribute("aria-label", `Закрыть критическое уведомление: ${item.name}`);
        closeButton.title = "Закрыть";
        closeButton.textContent = "×";
        closeButton.addEventListener("click", () => {
          card.remove();
          if (!criticalGrid.childElementCount) close();
        });
        symbol.className = "wallboard-critical-alert-symbol";
        symbol.setAttribute("aria-hidden", "true");
        symbol.textContent = "!";
        kicker.className = "wallboard-critical-alert-kicker";
        kicker.textContent = "ТРЕБУЕТ НЕМЕДЛЕННОГО ВНИМАНИЯ";
        title.textContent = "Critical";
        name.textContent = item.name;
        description.textContent = item.description;
        card.append(closeButton, symbol, kicker, title, name, description);
        return card;
      });
      criticalGrid.replaceChildren(...cards);
      criticalAlert.hidden = false;
      criticalTimer = window.setTimeout(close, 60_000);
      cards[cards.length - 1]?.querySelector("button")?.focus();
    };
    const sync = (items) => {
      if (items.some((item) => !seenCriticalIds.has(item.id))) show(items);
      // Recovery removes the id, so a later independent Critical is announced again.
      saveSeenCritical(items);
    };
    const controller = { show, sync, close };
    criticalAlert._criticalAlerts = controller;
    sync(criticalTargetsFrom(document));
    criticalAlert.addEventListener("click", (event) => {
      if (event.target === criticalAlert) close();
    });
    let refreshInFlight = false;
    const snapshotTimer = window.setInterval(async () => {
      if (!criticalAlert.isConnected) {
        window.clearInterval(snapshotTimer);
        if (criticalTimer) window.clearTimeout(criticalTimer);
        return;
      }
      if (refreshInFlight || document.hidden) return;
      refreshInFlight = true;
      try {
        const response = await fetch(criticalSource, {
          headers: { "X-Requested-With": "Monitoring-Maxval" },
          credentials: "same-origin",
          cache: "no-store",
          signal: AbortSignal.timeout(12_000),
        });
        if (!response.ok) throw new Error("Snapshot unavailable");
        const next = new DOMParser().parseFromString(await response.text(), "text/html");
        if (!next.querySelector("[data-critical-sources]")) throw new Error("Invalid snapshot");
        if (!criticalAlert.isConnected) return;
        document.querySelector("[data-wallboard]")?._updateSnapshot?.(next);
        sync(criticalTargetsFrom(next));
      } catch (_) {
        if (criticalAlert.isConnected) {
          const board = document.querySelector("[data-wallboard]");
          board?.classList.add("is-stale");
          const freshness = board?.querySelector("[data-wallboard-freshness]");
          if (freshness) freshness.title = "Не удалось обновить данные. Показано последнее полученное состояние.";
        }
      } finally { refreshInFlight = false; }
    }, 15_000);
    return controller;
  };

  const reinitializeDynamicPage = () => {
    const pushPanel = document.querySelector(".settings-push-panel");
    const smtpPanel = document.querySelector(".smtp-panel");
    if (pushPanel && smtpPanel && pushPanel.compareDocumentPosition(smtpPanel) & Node.DOCUMENT_POSITION_PRECEDING) {
      smtpPanel.before(pushPanel);
    }
    initPage();
    initSiteLayout();
    initWallboard();
    initCriticalAlerts();
    initCommunicationStatus();
    initChatPolling();
    initChatDrawer();
    initChatFullscreen();
    syncCurrentPushSubscription();
    syncPushState();
    showDefaultPasswordWarning();
    window.setTimeout(focusNavigationTarget, 0);
  };

  const initSiteLayout = () => {
    const form = document.querySelector("[data-site-layout-form]");
    const canvas = document.querySelector("[data-site-layout-canvas]");
    const palette = document.querySelector("[data-site-layout-palette]");
    const siteSwitch = document.querySelector("[data-site-layout-switch]");
    const scale = document.querySelector("[data-site-layout-scale]");
    const scaleValue = document.querySelector("[data-site-layout-scale-value]");
    if (!form || !canvas || form.dataset.ready) return;
    form.dataset.ready = "true";
    const applyScale = (value) => {
      const normalized = Math.max(50, Math.min(200, Number(value) || 100));
      canvas.style.setProperty("--site-layout-target-scale", String(normalized / 100));
      if (scale) {
        scale.value = String(normalized);
        scale.style.setProperty("--site-layout-scale-progress", `${((normalized - 50) / 150) * 100}%`);
      }
      if (scaleValue) scaleValue.textContent = `${normalized}%`;
    };
    applyScale(scale?.value || 100);
    scale?.addEventListener("input", () => {
      applyScale(scale.value);
      form.dataset.dirty = "true";
    });
    palette?.addEventListener("wheel", (event) => {
      if (palette.scrollWidth <= palette.clientWidth) return;
      event.preventDefault();
      palette.scrollLeft += event.deltaY || event.deltaX;
    }, { passive: false });
    let dragging = null;
    let selectedTargetIds = new Set();
    const selectedTargets = () => [...canvas.querySelectorAll("[data-layout-target]")]
      .filter((node) => selectedTargetIds.has(node.dataset.targetId));
    const renderSelection = () => {
      const existing = new Set([...canvas.querySelectorAll("[data-layout-target]")].map((node) => node.dataset.targetId));
      selectedTargetIds = new Set([...selectedTargetIds].filter((id) => existing.has(id)));
      canvas.querySelectorAll("[data-layout-target]").forEach((node) => {
        const selected = selectedTargetIds.has(node.dataset.targetId);
        node.classList.toggle("is-selected", selected);
        node.setAttribute("aria-pressed", String(selected));
      });
    };
    const clearSelection = () => {
      if (!selectedTargetIds.size) return;
      selectedTargetIds.clear();
      renderSelection();
    };
    const position = (event) => {
      const rect = canvas.getBoundingClientRect();
      return { x: Math.round(Math.max(0, Math.min(10000, (event.clientX - rect.left) / rect.width * 10000)) / 200) * 200,
        y: Math.round(Math.max(0, Math.min(10000, (event.clientY - rect.top) / rect.height * 10000)) / 200) * 200 };
    };
    const containsPoint = (element, event) => {
      if (!element) return false;
      const rect = element.getBoundingClientRect();
      return event.clientX >= rect.left && event.clientX <= rect.right
        && event.clientY >= rect.top && event.clientY <= rect.bottom;
    };
    const syncPositions = () => {
      const positions = [...canvas.querySelectorAll("[data-layout-target]")].map((node) => {
        const x = Number(node.dataset.layoutX);
        const y = Number(node.dataset.layoutY);
        return { id: Number(node.dataset.targetId), x, y };
      }).filter((item) => Number.isInteger(item.id) && Number.isFinite(item.x) && Number.isFinite(item.y));
      form.querySelector("[data-site-layout-positions]").value = JSON.stringify(positions);
      canvas.querySelector(".site-layout-empty")?.toggleAttribute("hidden", positions.length > 0);
      document.querySelectorAll("[data-layout-palette-target]").forEach((item) => {
        item.classList.toggle("is-placed", positions.some((positionItem) => positionItem.id === Number(item.dataset.targetId)));
      });
      return positions;
    };
    const moveToPointer = (node, event) => {
      const { x, y } = position(event);
      node.dataset.layoutX = String(x);
      node.dataset.layoutY = String(y);
      node.style.setProperty("left", `${x / 100}%`, "important");
      node.style.setProperty("top", `${y / 100}%`, "important");
    };
    const startDragging = (node, event, isNew = false) => {
      const targetId = node.dataset.targetId;
      const additive = event.ctrlKey || event.metaKey;
      if (additive && selectedTargetIds.has(targetId)) {
        selectedTargetIds.delete(targetId);
        renderSelection();
        event.preventDefault();
        return;
      }
      if (isNew || !additive && !selectedTargetIds.has(targetId)) {
        selectedTargetIds = new Set([targetId]);
      } else if (additive) {
        selectedTargetIds.add(targetId);
      }
      renderSelection();
      const originals = new Map(selectedTargets().map((item) => [item, {
        x: Number(item.dataset.layoutX), y: Number(item.dataset.layoutY),
      }]));
      dragging = {
        node, isNew, pointerId: event.pointerId, start: position(event), originals, moved: false,
      };
      event.currentTarget?.setPointerCapture?.(event.pointerId);
      document.body.classList.add("site-layout-dragging");
      event.preventDefault();
    };
    const bindCanvasTarget = (node) => {
      if (node.dataset.layoutDragReady) return;
      node.dataset.layoutDragReady = "true";
      const storedX = Number(node.dataset.layoutX);
      const storedY = Number(node.dataset.layoutY);
      if (Number.isFinite(storedX) && Number.isFinite(storedY)) {
        node.style.setProperty("left", `${storedX / 100}%`, "important");
        node.style.setProperty("top", `${storedY / 100}%`, "important");
      }
      node.addEventListener("pointerdown", (event) => startDragging(node, event));
      node.addEventListener("click", (event) => event.preventDefault());
      node.addEventListener("keydown", (event) => {
        if (event.key !== "Enter" && event.key !== " ") return;
        event.preventDefault();
        const targetId = node.dataset.targetId;
        if (event.ctrlKey || event.metaKey) {
          if (selectedTargetIds.has(targetId)) selectedTargetIds.delete(targetId);
          else selectedTargetIds.add(targetId);
        } else {
          selectedTargetIds = new Set([targetId]);
        }
        renderSelection();
      });
    };
    canvas.querySelectorAll("[data-layout-target]").forEach(bindCanvasTarget);
    document.querySelectorAll("[data-layout-palette-target]").forEach((paletteTarget) => paletteTarget.addEventListener("pointerdown", (event) => {
      const targetId = paletteTarget.dataset.targetId;
      let target = canvas.querySelector(`[data-layout-target][data-target-id="${targetId}"]`);
      const isNew = !target;
      if (!target) {
        target = paletteTarget.cloneNode(true);
        target.className = "site-layout-target";
        target.removeAttribute("data-layout-palette-target");
        target.setAttribute("data-layout-target", "");
        target.dataset.layoutX = "5000";
        target.dataset.layoutY = "10000";
        target.style.setProperty("left", "50%", "important");
        target.style.setProperty("top", "100%", "important");
        canvas.append(target);
        bindCanvasTarget(target);
      }
      startDragging(target, event, isNew);
    }));
    canvas.addEventListener("pointerdown", (event) => {
      if (event.button === 0 && !event.target.closest?.("[data-layout-target]")) clearSelection();
    });
    const moveSelectedToPointer = (event) => {
      if (!dragging) return;
      if (dragging.isNew) {
        if (containsPoint(canvas, event)) {
          moveToPointer(dragging.node, event);
          dragging.moved = true;
        }
        return;
      }
      const pointer = position(event);
      const requestedX = pointer.x - dragging.start.x;
      const requestedY = pointer.y - dragging.start.y;
      const originals = [...dragging.originals.values()];
      const deltaX = Math.max(-Math.min(...originals.map((item) => item.x)), Math.min(10000 - Math.max(...originals.map((item) => item.x)), requestedX));
      const deltaY = Math.max(-Math.min(...originals.map((item) => item.y)), Math.min(10000 - Math.max(...originals.map((item) => item.y)), requestedY));
      dragging.originals.forEach((original, item) => {
        const x = original.x + deltaX;
        const y = original.y + deltaY;
        item.dataset.layoutX = String(x);
        item.dataset.layoutY = String(y);
        item.style.setProperty("left", `${x / 100}%`, "important");
        item.style.setProperty("top", `${y / 100}%`, "important");
      });
      dragging.moved = dragging.moved || deltaX !== 0 || deltaY !== 0;
    };
    window.addEventListener("pointermove", (event) => {
      if (!dragging || event.pointerId !== dragging.pointerId) return;
      moveSelectedToPointer(event);
    });
    const finishDragging = (event, cancelled = false) => {
      if (!dragging || event.pointerId !== dragging.pointerId) return;
      const { node, isNew, originals, moved } = dragging;
      const nodes = [...originals.keys()];
      let changed = moved;
      if (!cancelled && containsPoint(palette, event)) {
        nodes.forEach((item) => selectedTargetIds.delete(item.dataset.targetId));
        nodes.forEach((item) => item.remove());
        changed = true;
      } else if (!cancelled && containsPoint(canvas, event)) {
        if (isNew) {
          moveToPointer(node, event);
          changed = true;
        }
      } else if (isNew) {
        selectedTargetIds.delete(node.dataset.targetId);
        node.remove();
      } else {
        originals.forEach((original, item) => {
          item.dataset.layoutX = String(original.x);
          item.dataset.layoutY = String(original.y);
          item.style.setProperty("left", `${original.x / 100}%`, "important");
          item.style.setProperty("top", `${original.y / 100}%`, "important");
        });
        changed = false;
      }
      dragging = null;
      document.body.classList.remove("site-layout-dragging");
      renderSelection();
      if (changed) {
        syncPositions();
        form.dataset.dirty = "true";
      }
    };
    window.addEventListener("pointerup", (event) => finishDragging(event));
    window.addEventListener("pointercancel", (event) => finishDragging(event, true));
    form.querySelector("[data-site-layout-clear]")?.addEventListener("click", () => {
      canvas.querySelectorAll("[data-layout-target]").forEach((node) => node.remove());
      clearSelection();
      syncPositions();
      form.dataset.dirty = "true";
    });
    siteSwitch?.addEventListener("change", () => {
      if (form.dataset.dirty === "true" && !window.confirm("Расположение не сохранено. Перейти к другой площадке?")) {
        siteSwitch.value = window.location.pathname;
        return;
      }
      window.location.assign(siteSwitch.value);
    });
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      syncPositions();
      const submitter = event.submitter;
      if (submitter) submitter.disabled = true;
      form.setAttribute("aria-busy", "true");
      try {
        const response = await fetch(form.action, {
          method: "POST",
          body: new FormData(form),
          credentials: "same-origin",
          headers: { "X-Requested-With": "Monitoring-Maxval" }
        });
        const responseUrl = new URL(response.url);
        const failure = responseUrl.searchParams.get("error");
        if (!response.ok || failure) throw new Error(failure || "Не удалось сохранить расположение");
        form.dataset.dirty = "false";
        showToast(responseUrl.searchParams.get("notice") || "Расположение объектов сохранено");
      } catch (error) {
        showToast(error.message || "Не удалось сохранить расположение", "error");
      } finally {
        if (submitter) submitter.disabled = false;
        form.removeAttribute("aria-busy");
      }
    });
    syncPositions();
  };

  const initWallboard = () => {
    const board = document.querySelector("[data-wallboard]");
    if (!board || board.dataset.ready) return;
    board.dataset.ready = "true";
    const serverClock = board.querySelector("[data-wallboard-server-clock] strong");
    if (serverClock) {
      const parts = serverClock.textContent.trim().split(":").map(Number);
      let seconds = parts.length === 3 && parts.every(Number.isFinite)
        ? parts[0] * 3600 + parts[1] * 60 + parts[2]
        : null;
      if (seconds !== null) {
        const renderServerClock = () => {
          seconds = (seconds + 1) % 86400;
          const hour = String(Math.floor(seconds / 3600)).padStart(2, "0");
          const minute = String(Math.floor(seconds % 3600 / 60)).padStart(2, "0");
          const second = String(seconds % 60).padStart(2, "0");
          serverClock.textContent = `${hour}:${minute}:${second}`;
        };
        const timer = window.setInterval(renderServerClock, 1000);
        window.addEventListener("pagehide", () => window.clearInterval(timer), { once: true });
      }
    }
    board.querySelectorAll("[data-wallboard-target]").forEach((node) => {
      const x = Number(node.dataset.layoutX);
      const y = Number(node.dataset.layoutY);
      const scale = Number(node.dataset.layoutScale);
      if (!Number.isFinite(x) || !Number.isFinite(y)) return;
      node.style.setProperty("left", `${x / 100}%`, "important");
      node.style.setProperty("top", `${y / 100}%`, "important");
      node.style.setProperty(
        "transform",
        `translate(-50%, -50%) scale(${Number.isFinite(scale) ? scale : 1})`,
        "important",
      );
    });
    const sites = [...board.querySelectorAll("[data-wallboard-site]")];
    const setExpandIcon = (button, expanded) => {
      const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      svg.setAttribute("viewBox", "0 0 24 24");
      svg.setAttribute("class", "wallboard-control-glyph");
      svg.setAttribute("aria-hidden", "true");
      const path = document.createElementNS(svg.namespaceURI, "path");
      path.setAttribute("d", expanded
        ? "M4 9h5V4M20 9h-5V4M4 15h5v5M20 15h-5v5"
        : "M9 4H4v5M15 4h5v5M4 15v5h5M20 15v5h-5");
      svg.append(path);
      button.replaceChildren(svg);
    };
    const sitesGrid = board.querySelector("[data-wallboard-sites]");
    const storageKey = "monitoring-wallboard-visible-sites";
    const scaleStorageKey = "monitoring-wallboard-site-scale-overrides";
    const panStorageKey = "monitoring-wallboard-site-pan-offsets";
    const gridSizeStorageKey = "monitoring-wallboard-site-grid-sizes";
    const siteOrderStorageKey = "monitoring-wallboard-site-order";
    let selectedIds = new Set(sites.map((node) => node.dataset.wallboardSite));
    let screenScales = {};
    let screenPans = {};
    let gridSizes = {};
    let siteOrder = sites.map((node) => node.dataset.wallboardSite);
    try {
      const stored = JSON.parse(localStorage.getItem(storageKey) || "[]");
      if (Array.isArray(stored)) {
        const known = new Set(sites.map((node) => node.dataset.wallboardSite));
        const restored = stored.filter((id) => known.has(String(id))).map(String);
        if (restored.length) selectedIds = new Set(restored);
      }
    } catch (_) { /* Keep all sites visible when browser storage is unavailable. */ }
    try {
      const storedScales = JSON.parse(localStorage.getItem(scaleStorageKey) || "{}");
      if (storedScales && typeof storedScales === "object" && !Array.isArray(storedScales)) {
        screenScales = storedScales;
      }
    } catch (_) { /* A malformed local preference must not affect the wallboard. */ }
    try {
      const storedOrder = JSON.parse(localStorage.getItem(siteOrderStorageKey) || "[]");
      if (Array.isArray(storedOrder)) {
        const known = new Set(siteOrder);
        const restored = storedOrder.map(String).filter((id, index, list) => known.has(id) && list.indexOf(id) === index);
        siteOrder = [...restored, ...siteOrder.filter((id) => !restored.includes(id))];
      }
    } catch (_) { /* Keep the server order when browser storage is unavailable. */ }
    try {
      const storedPans = JSON.parse(localStorage.getItem(panStorageKey) || "{}");
      if (storedPans && typeof storedPans === "object" && !Array.isArray(storedPans)) {
        screenPans = storedPans;
      }
    } catch (_) { /* A malformed local preference must not affect the wallboard. */ }
    try {
      const storedSizes = JSON.parse(localStorage.getItem(gridSizeStorageKey) || "{}");
      if (storedSizes && typeof storedSizes === "object" && !Array.isArray(storedSizes)) {
        gridSizes = storedSizes;
      }
    } catch (_) { /* A malformed local preference must not affect the wallboard. */ }
    const normalizeScreenScale = (value) => {
      const scale = Number(value);
      return Number.isFinite(scale) && scale >= 10 && scale <= 200 ? scale : 100;
    };
    const screenPan = (siteId) => {
      const stored = screenPans[siteId];
      const x = Number(stored?.x);
      const y = Number(stored?.y);
      return {
        x: Number.isFinite(x) ? x : 0,
        y: Number.isFinite(y) ? y : 0,
      };
    };
    const persistScreenPans = () => {
      try { localStorage.setItem(panStorageKey, JSON.stringify(screenPans)); }
      catch (_) { /* The current TV screen keeps the position without storage access. */ }
    };
    board.querySelectorAll("[data-wallboard-site-scale]").forEach((input) => {
      input.value = String(normalizeScreenScale(screenScales[input.dataset.wallboardSiteId]));
    });
    const orderedSites = (items) => [...items].sort(
      (left, right) => siteOrder.indexOf(left.dataset.wallboardSite) - siteOrder.indexOf(right.dataset.wallboardSite),
    );
    const selectedSites = () => orderedSites(sites.filter((node) => selectedIds.has(node.dataset.wallboardSite)));
    let focusedSiteId = null;
    let activeGrid = null;
    const normalizedTracks = (stored, count) => {
      if (!Array.isArray(stored) || stored.length !== count) return Array(count).fill(1);
      const tracks = stored.map(Number);
      return tracks.every((value) => Number.isFinite(value) && value >= 0.3)
        ? tracks
        : Array(count).fill(1);
    };
    const gridStorageKey = (visible, columns, rows) => (
      `${visible.map((site) => site.dataset.wallboardSite).join(",")}|${columns}x${rows}`
    );
    const setGridSize = (visible, useStoredSizes = true) => {
      const count = visible.length;
      const columns = count < 2 ? 1 : count < 5 ? 2 : count < 10 ? 3 : 4;
      const rows = Math.ceil(count / columns) || 1;
      const key = gridStorageKey(visible, columns, rows);
      const saved = useStoredSizes ? gridSizes[key] : null;
      const columnTracks = normalizedTracks(saved?.columns, columns);
      const rowTracks = normalizedTracks(saved?.rows, rows);
      sitesGrid?.style.setProperty("--wallboard-site-columns", String(columns), "important");
      sitesGrid?.style.setProperty("--wallboard-site-rows", String(rows), "important");
      sitesGrid?.style.setProperty(
        "grid-template-columns",
        columnTracks.map((value) => `minmax(0,${value}fr)`).join(" "),
        "important",
      );
      sitesGrid?.style.setProperty(
        "grid-template-rows",
        rowTracks.map((value) => `minmax(0,${value}fr)`).join(" "),
        "important",
      );
      activeGrid = { key, visible, columns, rows, columnTracks, rowTracks, useStoredSizes };
      visible.forEach((site) => {
        const handle = site.querySelector("[data-wallboard-site-resize]");
        if (handle) handle.hidden = !useStoredSizes || count < 2;
      });
      sites.filter((site) => !visible.includes(site)).forEach((site) => {
        const handle = site.querySelector("[data-wallboard-site-resize]");
        if (handle) handle.hidden = true;
      });
    };
    const densityFactor = (count) => {
      if (count < 2) return 1;
      if (count < 3) return 0.82;
      if (count < 5) return 0.68;
      if (count < 10) return 0.54;
      return 0.44;
    };
    const constrainedPan = (site, scale, requested) => {
      const canvas = site.querySelector(".wallboard-canvas");
      const rect = canvas?.getBoundingClientRect();
      const coordinates = [...site.querySelectorAll("[data-wallboard-target]")]
        .map((node) => ({ x: Number(node.dataset.layoutX), y: Number(node.dataset.layoutY) }))
        .filter(({ x, y }) => Number.isFinite(x) && Number.isFinite(y));
      if (!rect || !coordinates.length) return requested;
      const positions = coordinates.map(({ x, y }) => ({
        x: (50 + ((x / 100) - 50) * scale) * rect.width / 100,
        y: (50 + ((y / 100) - 50) * scale) * rect.height / 100,
      }));
      const clampAxis = (values, size, offset) => {
        const minimum = Math.min(...values);
        const maximum = Math.max(...values);
        const margin = Math.min(20, size * 0.08);
        if (maximum - minimum > size - margin * 2) return Math.round(size / 2 - (minimum + maximum) / 2);
        return Math.round(Math.min(size - margin - maximum, Math.max(margin - minimum, offset)));
      };
      return {
        x: clampAxis(positions.map((position) => position.x), rect.width, requested.x),
        y: clampAxis(positions.map((position) => position.y), rect.height, requested.y),
      };
    };
    const centerSiteObjects = (site, render = true) => {
      const siteId = site?.dataset.wallboardSite;
      const canvas = site?.querySelector(".wallboard-canvas");
      const rect = canvas?.getBoundingClientRect();
      const scale = normalizeScreenScale(site?.querySelector("[data-wallboard-site-scale]")?.value) / 100;
      const coordinates = [...(site?.querySelectorAll("[data-wallboard-target]") || [])]
        .map((node) => ({ x: Number(node.dataset.layoutX), y: Number(node.dataset.layoutY) }))
        .filter(({ x, y }) => Number.isFinite(x) && Number.isFinite(y));
      if (!siteId || !rect || !coordinates.length) return;
      const averageX = coordinates.reduce((sum, item) => sum + 50 + ((item.x / 100) - 50) * scale, 0) / coordinates.length;
      const averageY = coordinates.reduce((sum, item) => sum + 50 + ((item.y / 100) - 50) * scale, 0) / coordinates.length;
      screenPans[siteId] = constrainedPan(site, scale, {
        x: (50 - averageX) * rect.width / 100,
        y: (50 - averageY) * rect.height / 100,
      });
      if (render) {
        persistScreenPans();
        renderGrid();
      }
    };
    const applyTargetScales = (visible) => {
      const factor = densityFactor(visible.length);
      visible.forEach((site) => {
        const screenScale = normalizeScreenScale(
          site.querySelector("[data-wallboard-site-scale]")?.value,
        ) / 100;
        const requestedPan = screenPan(site.dataset.wallboardSite);
        const pan = constrainedPan(site, screenScale, requestedPan);
        screenPans[site.dataset.wallboardSite] = pan;
        const canvas = site.querySelector(".wallboard-canvas");
        canvas?.style.setProperty("background-position", `${pan.x}px ${pan.y}px`, "important");
        site.querySelectorAll("[data-wallboard-target]").forEach((node) => {
          const saved = Number(node.dataset.layoutScale);
          const x = Number(node.dataset.layoutX);
          const y = Number(node.dataset.layoutY);
          const effective = (Number.isFinite(saved) ? saved : 1) * screenScale * factor;
          // The TV control scales the whole layout about the canvas centre, not only icons.
          if (Number.isFinite(x)) {
            node.style.setProperty("left", `calc(${50 + ((x / 100) - 50) * screenScale}% + ${pan.x}px)`, "important");
          }
          if (Number.isFinite(y)) {
            node.style.setProperty("top", `calc(${50 + ((y / 100) - 50) * screenScale}% + ${pan.y}px)`, "important");
          }
          node.style.setProperty("transform", `translate(-50%, -50%) scale(${effective})`, "important");
        });
      });
      board.querySelectorAll("[data-wallboard-site-scale]").forEach((input) => {
        const output = input.parentElement?.querySelector("[data-wallboard-site-scale-value]");
        const saved = Number(input.value) || 100;
        output?.replaceChildren(`${saved}%`);
        const toggle = input.closest("[data-wallboard-site]")?.querySelector("[data-wallboard-site-scale-toggle]");
        if (toggle) toggle.textContent = `${saved}%`;
      });
    };
    const syncSiteOptions = () => {
      board.querySelectorAll("[data-wallboard-site-toggle]").forEach((button) => {
        const selected = selectedIds.has(button.dataset.wallboardSiteId);
        button.classList.toggle("is-selected", selected);
        button.setAttribute("aria-pressed", String(selected));
      });
      board.querySelectorAll("[data-wallboard-site-focus]").forEach((button) => {
        const focused = focusedSiteId === button.dataset.wallboardSiteId;
        button.setAttribute("aria-pressed", String(focused));
        setExpandIcon(button, focused);
        button.title = focused ? "Вернуть общую сетку" : "Развернуть площадку на весь экран";
        button.setAttribute("aria-label", `${button.title}: ${button.closest("[data-wallboard-site]")?.querySelector("h1")?.textContent || "площадка"}`);
      });
    };
    const renderGrid = () => {
      const selected = selectedSites();
      if (focusedSiteId && !selected.some((node) => node.dataset.wallboardSite === focusedSiteId)) {
        focusedSiteId = null;
      }
      const visible = focusedSiteId
        ? selected.filter((node) => node.dataset.wallboardSite === focusedSiteId)
        : selected;
      sites.forEach((node) => { node.hidden = !visible.includes(node); });
      visible.forEach((node, index) => node.style.setProperty("order", String(index), "important"));
      setGridSize(visible, !focusedSiteId);
      applyTargetScales(visible);
      const layoutLink = board.querySelector("[data-wallboard-layout-link]");
      if (layoutLink && visible[0]) layoutLink.href = `/sites/${visible[0].dataset.wallboardSite}/layout`;
      syncSiteOptions();
    };
    const saveSelection = () => localStorage.setItem(storageKey, JSON.stringify([...selectedIds]));
    const saveSiteOrder = () => {
      try { localStorage.setItem(siteOrderStorageKey, JSON.stringify(siteOrder)); }
      catch (_) { /* The order remains active until the current TV page is closed. */ }
    };
    let rotationTimer = null;
    let rotationIndex = 0;
    const rotationButton = board.querySelector("[data-wallboard-rotation]");
    const stopRotation = (leaveFullscreen = true) => {
      if (rotationTimer) window.clearInterval(rotationTimer);
      rotationTimer = null;
      board.classList.remove("is-rotating");
      rotationButton?.setAttribute("aria-pressed", "false");
      if (rotationButton) rotationButton.textContent = "Ротация";
      renderGrid();
      if (leaveFullscreen && document.fullscreenElement) document.exitFullscreen?.();
    };
    const renderRotationSite = () => {
      const selected = selectedSites();
      if (!selected.length) return stopRotation();
      rotationIndex %= selected.length;
      sites.forEach((node) => { node.hidden = node !== selected[rotationIndex]; });
      setGridSize([selected[rotationIndex]], false);
      applyTargetScales([selected[rotationIndex]]);
    };
    const startRotation = async () => {
      const selected = selectedSites();
      if (!selected.length) return;
      focusedSiteId = null;
      board.classList.add("is-rotating");
      rotationButton?.setAttribute("aria-pressed", "true");
      if (rotationButton) rotationButton.textContent = "Остановить";
      rotationIndex = 0;
      renderRotationSite();
      if (selected.length > 1) rotationTimer = window.setInterval(() => {
        rotationIndex += 1;
        renderRotationSite();
      }, 15000);
      if (!document.fullscreenElement) {
        try { await document.documentElement.requestFullscreen?.(); }
        catch (_) { showToast("Полноэкранный режим не поддерживается браузером", "error"); }
      }
    };
    renderGrid();
    const menu = board.querySelector("[data-wallboard-sites-menu]");
    const menuButton = board.querySelector("[data-wallboard-sites-menu-toggle]");
    const setMenuOpen = (open) => {
      if (!menu) return;
      menu.hidden = !open;
      menuButton?.setAttribute("aria-expanded", String(open));
    };
    menuButton?.addEventListener("click", () => setMenuOpen(menu?.hidden));
    board.querySelector("[data-wallboard-sites-menu-close]")?.addEventListener("click", () => setMenuOpen(false));
    board.querySelectorAll("[data-wallboard-site-toggle]").forEach((button) => button.addEventListener("click", () => {
      const id = button.dataset.wallboardSiteId;
      if (selectedIds.has(id) && selectedIds.size === 1) return showToast("Нужно оставить хотя бы одну площадку", "error");
      if (selectedIds.has(id)) selectedIds.delete(id);
      else selectedIds.add(id);
      if (rotationTimer || board.classList.contains("is-rotating")) stopRotation();
      saveSelection();
      renderGrid();
    }));
    board.querySelectorAll("[data-wallboard-site-drag]").forEach((header) => header.addEventListener("pointerdown", (event) => {
      if (event.button !== 0 || event.target.closest("button, a, input, select, label") || !activeGrid?.useStoredSizes) return;
      const source = header.closest("[data-wallboard-site]");
      if (!source || activeGrid.visible.length < 2) return;
      const startX = event.clientX;
      const startY = event.clientY;
      let target = null;
      let moved = false;
      const clearTarget = () => {
        sites.forEach((site) => site.classList.remove("is-site-drop-target"));
      };
      const move = (moveEvent) => {
        if (!moved && Math.hypot(moveEvent.clientX - startX, moveEvent.clientY - startY) < 6) return;
        moved = true;
        sitesGrid?.classList.add("is-site-dragging");
        source.classList.add("is-site-dragging");
        const candidate = document.elementFromPoint(moveEvent.clientX, moveEvent.clientY)
          ?.closest?.("[data-wallboard-site]");
        clearTarget();
        target = candidate && candidate !== source && !candidate.hidden ? candidate : null;
        target?.classList.add("is-site-drop-target");
      };
      const finish = () => {
        window.removeEventListener("pointermove", move);
        window.removeEventListener("pointerup", finish);
        sitesGrid?.classList.remove("is-site-dragging");
        source.classList.remove("is-site-dragging");
        clearTarget();
        if (!moved || !target) return;
        const sourceIndex = siteOrder.indexOf(source.dataset.wallboardSite);
        const targetIndex = siteOrder.indexOf(target.dataset.wallboardSite);
        if (sourceIndex < 0 || targetIndex < 0 || sourceIndex === targetIndex) return;
        [siteOrder[sourceIndex], siteOrder[targetIndex]] = [siteOrder[targetIndex], siteOrder[sourceIndex]];
        saveSiteOrder();
        renderGrid();
        showToast("Положение площадок на TV-экране сохранено");
      };
      event.preventDefault();
      header.setPointerCapture?.(event.pointerId);
      window.addEventListener("pointermove", move);
      window.addEventListener("pointerup", finish, { once: true });
    }));
    const actionsMenu = board.querySelector("[data-wallboard-actions-menu]");
    const actionsMenuButton = board.querySelector("[data-wallboard-actions-menu-toggle]");
    const testsMenu = board.querySelector("[data-wallboard-tests-menu]");
    const testsMenuButton = board.querySelector("[data-wallboard-tests-menu-toggle]");
    const setTestsMenuOpen = (open) => {
      if (!testsMenu) return;
      testsMenu.hidden = !open;
      testsMenuButton?.setAttribute("aria-expanded", String(open));
    };
    const setActionsMenuOpen = (open) => {
      if (!actionsMenu) return;
      actionsMenu.hidden = !open;
      actionsMenuButton?.setAttribute("aria-expanded", String(open));
      if (!open) setTestsMenuOpen(false);
    };
    actionsMenuButton?.addEventListener("click", () => setActionsMenuOpen(actionsMenu?.hidden));
    testsMenuButton?.addEventListener("click", () => setTestsMenuOpen(testsMenu?.hidden));
    document.addEventListener("pointerdown", (event) => {
      if (!actionsMenu || actionsMenu.hidden) return;
      if (actionsMenu.contains(event.target) || actionsMenuButton?.contains(event.target)) return;
      setActionsMenuOpen(false);
    });
    board.querySelectorAll("[data-wallboard-preview-target]").forEach((node) => {
      const x = Number(node.dataset.layoutX);
      const y = Number(node.dataset.layoutY);
      if (!Number.isFinite(x) || !Number.isFinite(y)) return;
      node.style.setProperty("left", `${x / 100}%`, "important");
      node.style.setProperty("top", `${y / 100}%`, "important");
    });
    board.querySelectorAll("[data-wallboard-site-scale]").forEach((input) => {
      const saveScale = () => {
        const value = normalizeScreenScale(input.value);
        input.value = String(value);
        screenScales[input.dataset.wallboardSiteId] = value;
        try {
          localStorage.setItem(scaleStorageKey, JSON.stringify(screenScales));
        } catch (_) { /* The current TV screen keeps the scale even without storage access. */ }
        renderGrid();
        showToast("Масштаб TV-экрана сохранён");
      };
      input.addEventListener("input", renderGrid);
      input.addEventListener("change", saveScale);
    });
    board.querySelectorAll("[data-wallboard-site-center]").forEach((button) => button.addEventListener("click", () => {
      centerSiteObjects(button.closest("[data-wallboard-site]"));
      showToast("Объекты площадки центрированы");
    }));
    board.querySelectorAll("[data-wallboard-site-scale-toggle]").forEach((button) => button.addEventListener("click", () => {
      const site = button.closest("[data-wallboard-site]");
      const panel = site?.querySelector("[data-wallboard-site-scale-panel]");
      if (!panel) return;
      const expanded = panel.hidden;
      panel.hidden = !expanded;
      button.setAttribute("aria-expanded", String(expanded));
      if (expanded) panel.querySelector("input")?.focus();
    }));
    const resizeTracks = (tracks, index, deltaPixels, totalPixels) => {
      if (tracks.length < 2 || !Number.isFinite(totalPixels) || totalPixels <= 0) return [...tracks];
      const total = tracks.reduce((sum, value) => sum + value, 0);
      const minimum = 0.3;
      const next = [...tracks];
      const requested = tracks[index] + (deltaPixels / totalPixels) * total;
      next[index] = Math.max(minimum, Math.min(total - minimum * (tracks.length - 1), requested));
      const remaining = total - next[index];
      const otherTotal = total - tracks[index];
      tracks.forEach((value, itemIndex) => {
        if (itemIndex !== index) next[itemIndex] = remaining * value / otherTotal;
      });
      return next;
    };
    board.querySelectorAll("[data-wallboard-site-resize]").forEach((handle) => {
      handle.addEventListener("pointerdown", (event) => {
        if (event.button !== 0 || !activeGrid?.useStoredSizes) return;
        const site = handle.closest("[data-wallboard-site]");
        const siteIndex = activeGrid.visible.indexOf(site);
        if (siteIndex < 0 || activeGrid.visible.length < 2) return;
        event.preventDefault();
        event.stopPropagation();
        handle.setPointerCapture?.(event.pointerId);
        const startX = event.clientX;
        const startY = event.clientY;
        const startColumns = [...activeGrid.columnTracks];
        const startRows = [...activeGrid.rowTracks];
        const columnIndex = siteIndex % activeGrid.columns;
        const rowIndex = Math.floor(siteIndex / activeGrid.columns);
        const gridRect = sitesGrid.getBoundingClientRect();
        sitesGrid.classList.add("is-resizing");
        const move = (moveEvent) => {
          activeGrid.columnTracks = resizeTracks(
            startColumns,
            columnIndex,
            moveEvent.clientX - startX,
            gridRect.width,
          );
          activeGrid.rowTracks = resizeTracks(
            startRows,
            rowIndex,
            moveEvent.clientY - startY,
            gridRect.height,
          );
          sitesGrid.style.setProperty(
            "grid-template-columns",
            activeGrid.columnTracks.map((value) => `minmax(0,${value}fr)`).join(" "),
            "important",
          );
          sitesGrid.style.setProperty(
            "grid-template-rows",
            activeGrid.rowTracks.map((value) => `minmax(0,${value}fr)`).join(" "),
            "important",
          );
        };
        const finish = () => {
          sitesGrid.classList.remove("is-resizing");
          window.removeEventListener("pointermove", move);
          window.removeEventListener("pointerup", finish);
          gridSizes[activeGrid.key] = {
            columns: activeGrid.columnTracks,
            rows: activeGrid.rowTracks,
          };
          try { localStorage.setItem(gridSizeStorageKey, JSON.stringify(gridSizes)); }
          catch (_) { /* Resized grid remains active for the current session. */ }
        };
        window.addEventListener("pointermove", move);
        window.addEventListener("pointerup", finish, { once: true });
      });
    });
    board.querySelector("[data-wallboard-sites-size-reset]")?.addEventListener("click", () => {
      gridSizes = {};
      try { localStorage.removeItem(gridSizeStorageKey); }
      catch (_) { /* The current screen can still be reset without storage access. */ }
      screenPans = {};
      sites.forEach((site) => centerSiteObjects(site, false));
      persistScreenPans();
      renderGrid();
      showToast("Размеры площадок и положение объектов сброшены");
    });
    board.querySelectorAll(".wallboard-canvas").forEach((canvas) => {
      const site = canvas.closest("[data-wallboard-site]");
      const siteId = site?.dataset.wallboardSite;
      if (!siteId) return;
      canvas.addEventListener("pointerdown", (event) => {
        if (event.button !== 0 || event.target.closest?.("[data-wallboard-target]")) return;
        event.preventDefault();
        const initial = screenPan(siteId);
        const startX = event.clientX;
        const startY = event.clientY;
        canvas.classList.add("is-panning");
        const move = (moveEvent) => {
          screenPans[siteId] = {
            x: Math.round(initial.x + moveEvent.clientX - startX),
            y: Math.round(initial.y + moveEvent.clientY - startY),
          };
          renderGrid();
        };
        const finish = () => {
          canvas.classList.remove("is-panning");
          window.removeEventListener("pointermove", move);
          window.removeEventListener("pointerup", finish);
          persistScreenPans();
        };
        window.addEventListener("pointermove", move);
        window.addEventListener("pointerup", finish, { once: true });
      });
    });
    board.querySelectorAll("[data-wallboard-site-focus]").forEach((button) => button.addEventListener("click", () => {
      if (rotationTimer || board.classList.contains("is-rotating")) stopRotation();
      focusedSiteId = focusedSiteId === button.dataset.wallboardSiteId
        ? null
        : button.dataset.wallboardSiteId;
      renderGrid();
    }));
    rotationButton?.addEventListener("click", () => {
      if (rotationTimer || board.classList.contains("is-rotating")) stopRotation();
      else void startRotation();
    });
    window.addEventListener("resize", () => renderGrid(), { passive: true });
    const detail = document.querySelector("[data-wallboard-detail]");
    const serviceStatusClasses = new Set([
      "up", "down", "unknown", "disabled", "off_hours", "waiting_primary", "waiting_site",
    ]);
    const healthStatusClasses = new Set([
      "ok", "warning", "critical", "offline", "site_unreachable", "unknown", "disabled", "off_hours",
    ]);
    const renderTargetHealth = (serialized) => {
      const status = detail?.querySelector("[data-wallboard-detail-health-status]");
      const reason = detail?.querySelector("[data-wallboard-detail-health-reason]");
      if (!status || !reason) return;
      let health = {};
      try {
        const parsed = JSON.parse(serialized || "{}");
        health = parsed && typeof parsed === "object" ? parsed : {};
      } catch (_error) {
        health = {};
      }
      const state = healthStatusClasses.has(health.state) ? health.state : "unknown";
      status.className = `wallboard-detail-health-status state-${state}`;
      status.textContent = health.label || "Нет данных";
      reason.textContent = health.reason || "";
      reason.hidden = !health.reason;
    };
    const renderTargetServices = (serialized) => {
      const list = detail?.querySelector("[data-wallboard-detail-services]");
      const empty = detail?.querySelector("[data-wallboard-detail-services-empty]");
      if (!list || !empty) return;
      let services = [];
      try {
        const parsed = JSON.parse(serialized || "[]");
        services = Array.isArray(parsed) ? parsed : [];
      } catch (_error) {
        services = [];
      }
      list.replaceChildren();
      empty.hidden = services.length > 0;
      services.forEach((service) => {
        const row = document.createElement("li");
        const name = document.createElement("strong");
        const kind = document.createElement("small");
        const status = document.createElement("span");
        const state = serviceStatusClasses.has(service.status) ? service.status : "unknown";
        name.textContent = service.name || "Сервис";
        kind.textContent = `${service.is_primary ? "Основная" : "Сервис"} · ${(service.checker_type || "").toUpperCase()}`;
        status.className = `wallboard-detail-service-status state-${state}`;
        status.textContent = service.label || "Нет данных";
        row.append(name, kind, status);
        list.append(row);
      });
    };
    let selectedTarget = null;
    const showTargetDetail = (node) => {
      selectedTarget?.classList.remove("is-selected");
      selectedTarget = node;
      node.classList.add("is-selected");
      detail.querySelector("[data-wallboard-detail-title]").textContent = node.dataset.targetName;
      detail.querySelector("[data-wallboard-detail-text]").textContent = node.dataset.targetDetail;
      renderTargetHealth(node.dataset.targetHealth);
      renderTargetServices(node.dataset.targetServices);
      detail.hidden = false;
    };
    board.addEventListener("click", (event) => {
      const node = event.target.closest("[data-wallboard-target]");
      if (node) showTargetDetail(node);
    });
    const close = () => {
      detail.hidden = true;
      selectedTarget?.classList.remove("is-selected");
      selectedTarget?.focus({ preventScroll: true });
      selectedTarget = null;
    };
    document.querySelector("[data-wallboard-detail-close]")?.addEventListener("click", close);
    detail?.addEventListener("click", (event) => { if (event.target === detail) close(); });
    const statusDialog = document.querySelector("[data-wallboard-status-dialog]");
    const statusToggles = [...board.querySelectorAll("[data-wallboard-status-toggle]")];
    const closeStatusDialog = () => {
      if (statusDialog) statusDialog.hidden = true;
      statusToggles.forEach((button) => button.setAttribute("aria-expanded", "false"));
    };
    statusToggles.forEach((button) => button.addEventListener("click", () => {
      if (!statusDialog) return;
      if (!statusDialog.hidden && button.getAttribute("aria-expanded") === "true") {
        closeStatusDialog();
        return;
      }
      const status = button.dataset.wallboardStatus;
      statusDialog.querySelector("[data-wallboard-status-title]").textContent = button.dataset.wallboardStatusTitle || "Состояние";
      statusDialog.querySelectorAll("[data-wallboard-status-list]").forEach((list) => {
        list.hidden = list.dataset.wallboardStatusList !== status;
      });
      statusDialog.hidden = false;
      statusToggles.forEach((item) => item.setAttribute("aria-expanded", String(item === button)));
      const bounds = button.getBoundingClientRect();
      const menuWidth = statusDialog.offsetWidth;
      const menuHeight = statusDialog.offsetHeight;
      const margin = 8;
      const left = Math.min(Math.max(margin, bounds.left), window.innerWidth - menuWidth - margin);
      const below = bounds.bottom + margin;
      const top = below + menuHeight <= window.innerHeight
        ? below
        : Math.max(margin, bounds.top - menuHeight - margin);
      statusDialog.style.left = `${left}px`;
      statusDialog.style.top = `${top}px`;
    }));
    document.querySelector("[data-wallboard-status-close]")?.addEventListener("click", closeStatusDialog);
    document.addEventListener("pointerdown", (event) => {
      if (!statusDialog || statusDialog.hidden) return;
      if (statusDialog.contains(event.target) || statusToggles.some((button) => button.contains(event.target))) return;
      closeStatusDialog();
    });
    const criticalAlerts = initCriticalAlerts();
    board.querySelector("[data-wallboard-critical-test]")?.addEventListener("click", () => {
      criticalAlerts?.show([{
        id: "wallboard-critical-test",
        name: "Тестовое оповещение",
        description: "Так будет выглядеть сообщение при появлении критического сбоя объекта.",
      }]);
      setActionsMenuOpen(false);
    });
    board.querySelector("[data-wallboard-critical-burst-test]")?.addEventListener("click", () => {
      criticalAlerts?.show(Array.from({ length: 10 }, (_unused, index) => ({
        id: `wallboard-critical-burst-${index + 1}`,
        name: `Тестовый Critical №${index + 1}`,
        description: "Тест массового критического оповещения TV-экрана.",
      })));
      setActionsMenuOpen(false);
    });
    const eventsPanel = board.querySelector("[data-wallboard-events]");
    const eventsDragHandle = board.querySelector("[data-wallboard-events-drag]");
    const eventsResetButton = board.querySelector("[data-wallboard-events-reset]");
    const eventsCloseButton = board.querySelector("[data-wallboard-events-close]");
    const eventsCollapseButton = board.querySelector("[data-wallboard-events-collapse]");
    const eventsFontInput = board.querySelector("[data-wallboard-events-font]");
    const eventsFontValue = board.querySelector("[data-wallboard-events-font-value]");
    const eventsLayoutKey = "monitoring-wallboard-events-layout";
    const eventsHiddenKey = "monitoring-wallboard-events-hidden";
    const eventPanelMargin = 8;
    const normalizeEventsFont = (value) => {
      const size = Number(value);
      return Number.isFinite(size) && size >= 50 && size <= 200 ? size : 100;
    };
    const applyEventsFont = (value) => {
      const size = normalizeEventsFont(value);
      eventsPanel?.style.setProperty("--wallboard-events-font-scale", String(size / 100));
      if (eventsFontInput) eventsFontInput.value = String(size);
      if (eventsFontValue) eventsFontValue.textContent = `${size}%`;
    };
    const setEventsCollapsed = (collapsed) => {
      if (!eventsPanel) return;
      eventsPanel.classList.toggle("is-collapsed", collapsed);
      eventsCollapseButton?.setAttribute("aria-expanded", String(!collapsed));
      if (eventsCollapseButton) {
        eventsCollapseButton.textContent = collapsed ? "+" : "−";
        eventsCollapseButton.title = collapsed ? "Развернуть окно событий" : "Свернуть в одну строку";
        eventsCollapseButton.setAttribute("aria-label", eventsCollapseButton.title);
      }
    };
    const persistEventsLayout = () => {
      if (!eventsPanel || eventsPanel.hidden) return;
      const bounds = eventsPanel.getBoundingClientRect();
      try {
        localStorage.setItem(eventsLayoutKey, JSON.stringify({
          version: 2,
          left: Math.round(bounds.left), top: Math.round(bounds.top),
          width: Math.round(bounds.width), height: Math.round(bounds.height),
          fontSize: normalizeEventsFont(eventsFontInput?.value),
          collapsed: eventsPanel.classList.contains("is-collapsed"),
        }));
      } catch (_) { /* The current TV screen still keeps its layout without storage access. */ }
    };
    const resetEventsLayout = () => {
      if (!eventsPanel) return;
      eventsPanel.hidden = false;
      eventsPanel.style.removeProperty("left");
      eventsPanel.style.removeProperty("top");
      eventsPanel.style.removeProperty("bottom");
      eventsPanel.style.removeProperty("width");
      eventsPanel.style.removeProperty("height");
      setEventsCollapsed(false);
      applyEventsFont(100);
      try {
        localStorage.removeItem(eventsLayoutKey);
        localStorage.removeItem(eventsHiddenKey);
      } catch (_) { /* Ignore unavailable storage. */ }
    };
    if (eventsPanel) {
      try {
        const stored = JSON.parse(localStorage.getItem(eventsLayoutKey) || "null");
        if (stored?.version === 2 && [stored.left, stored.top, stored.width, stored.height].every(Number.isFinite)) {
          eventsPanel.style.left = `${stored.left}px`;
          eventsPanel.style.top = `${stored.top}px`;
          eventsPanel.style.bottom = "auto";
          eventsPanel.style.width = `${stored.width}px`;
          eventsPanel.style.height = `${stored.height}px`;
        }
        applyEventsFont(stored?.fontSize);
        setEventsCollapsed(stored?.collapsed === true);
        eventsPanel.hidden = localStorage.getItem(eventsHiddenKey) === "true";
      } catch (_) { /* Default lower-left placement remains usable. */ }
      if ("ResizeObserver" in window) {
        let resizeTimer = null;
        new ResizeObserver(() => {
          if (resizeTimer) window.clearTimeout(resizeTimer);
          resizeTimer = window.setTimeout(persistEventsLayout, 120);
        }).observe(eventsPanel);
      }
    }
    eventsDragHandle?.addEventListener("pointerdown", (event) => {
      if (!eventsPanel || event.button !== 0 || event.target.closest?.("button, input, label, output")) return;
      event.preventDefault();
      const bounds = eventsPanel.getBoundingClientRect();
      const offsetX = event.clientX - bounds.left;
      const offsetY = event.clientY - bounds.top;
      const move = (moveEvent) => {
        const current = eventsPanel.getBoundingClientRect();
        const left = Math.min(Math.max(eventPanelMargin, moveEvent.clientX - offsetX), window.innerWidth - current.width - eventPanelMargin);
        const top = Math.min(Math.max(eventPanelMargin, moveEvent.clientY - offsetY), window.innerHeight - current.height - eventPanelMargin);
        eventsPanel.style.left = `${left}px`;
        eventsPanel.style.top = `${top}px`;
        eventsPanel.style.bottom = "auto";
      };
      const finish = () => {
        window.removeEventListener("pointermove", move);
        window.removeEventListener("pointerup", finish);
        persistEventsLayout();
      };
      window.addEventListener("pointermove", move);
      window.addEventListener("pointerup", finish, { once: true });
    });
    eventsFontInput?.addEventListener("input", () => applyEventsFont(eventsFontInput.value));
    eventsFontInput?.addEventListener("change", persistEventsLayout);
    eventsCollapseButton?.addEventListener("click", () => {
      setEventsCollapsed(!eventsPanel?.classList.contains("is-collapsed"));
      persistEventsLayout();
    });
    eventsCloseButton?.addEventListener("click", () => {
      if (!eventsPanel) return;
      eventsPanel.hidden = true;
      try { localStorage.setItem(eventsHiddenKey, "true"); }
      catch (_) { /* The event window still closes for the current page. */ }
    });
    eventsResetButton?.addEventListener("click", resetEventsLayout);
    const syncEmptyCounts = () => board.querySelectorAll("[data-wallboard-status-toggle]").forEach((node) => {
      node.classList.toggle("is-empty", Number(node.querySelector("b")?.textContent) === 0);
    });
    syncEmptyCounts();
    // Reuse the existing Critical snapshot GET. Update presentation in place,
    // keeping pan, focus, rotation, sliders and event-window geometry intact.
    board._updateSnapshot = (next) => {
      const nextBoard = next.querySelector("[data-wallboard]");
      if (!nextBoard) return;
      board.classList.remove("is-stale");
      board.querySelector("[data-wallboard-freshness]")?.removeAttribute("title");
      const copyContents = (current, fresh) => {
        if (current && fresh && current.innerHTML !== fresh.innerHTML) {
          current.replaceChildren(...[...fresh.childNodes].map((child) => child.cloneNode(true)));
        }
      };
      copyContents(board.querySelector("[data-wallboard-freshness]"), nextBoard.querySelector("[data-wallboard-freshness]"));
      const freshCounts = [...nextBoard.querySelectorAll("[data-wallboard-status-toggle]")];
      statusToggles.forEach((node) => copyContents(node.querySelector("b"), freshCounts.find((item) => item.dataset.wallboardStatus === node.dataset.wallboardStatus)?.querySelector("b")));
      syncEmptyCounts();
      const freshOptions = [...nextBoard.querySelectorAll("[data-wallboard-site-toggle]")];
      board.querySelectorAll("[data-wallboard-site-toggle]").forEach((node) => {
        const fresh = freshOptions.find((item) => item.dataset.wallboardSiteId === node.dataset.wallboardSiteId);
        if (!fresh) return;
        copyContents(node.querySelector(".wallboard-site-option-preview"), fresh.querySelector(".wallboard-site-option-preview"));
        copyContents(node.querySelector("strong"), fresh.querySelector("strong"));
        copyContents(node.querySelector("small"), fresh.querySelector("small"));
        node.querySelectorAll("[data-wallboard-preview-target]").forEach((point) => {
          point.style.setProperty("left", `${Number(point.dataset.layoutX) / 100}%`, "important");
          point.style.setProperty("top", `${Number(point.dataset.layoutY) / 100}%`, "important");
        });
      });
      const freshMeters = [...nextBoard.querySelectorAll(".wallboard-telemetry > div")];
      board.querySelectorAll(".wallboard-telemetry > div").forEach((node, index) => {
        const fresh = freshMeters[index];
        if (!fresh) return;
        const changed = node.querySelector(".telemetry-value")?.textContent !== fresh.querySelector(".telemetry-value")?.textContent;
        node.className = fresh.className;
        node.title = fresh.title;
        node.style.cssText = fresh.style.cssText;
        copyContents(node, fresh);
        if (changed) {
          node.classList.add("is-data-changed");
          window.setTimeout(() => node.classList.remove("is-data-changed"), 2000);
        }
      });
      const freshSites = new Map([...nextBoard.querySelectorAll("[data-wallboard-site]")].map((node) => [node.dataset.wallboardSite, node]));
      sites.forEach((site) => {
        const fresh = freshSites.get(site.dataset.wallboardSite);
        const canvas = site.querySelector(".wallboard-canvas");
        if (!fresh) { canvas.querySelectorAll("[data-wallboard-target]").forEach((node) => node.remove()); return; }
        site.className = fresh.className;
        ["h1", ".wallboard-site-summary", ".wallboard-site-stamp"].forEach((selector) => copyContents(site.querySelector(selector), fresh.querySelector(selector)));
        const freshTargets = new Map([...fresh.querySelectorAll("[data-wallboard-target]")].map((node) => [node.dataset.targetId, node]));
        canvas.querySelectorAll("[data-wallboard-target]").forEach((node) => {
          const updated = freshTargets.get(node.dataset.targetId);
          if (!updated) { if (node === selectedTarget) close(); node.remove(); return; }
          const previous = JSON.parse(node.dataset.targetHealth || "{}").state;
          const current = JSON.parse(updated.dataset.targetHealth || "{}").state;
          node.className = updated.className;
          Object.assign(node.dataset, updated.dataset);
          copyContents(node, updated);
          if (previous !== current) {
            const effect = current === "ok" ? "is-recovered" : "is-state-changed";
            node.classList.add(effect);
            window.setTimeout(() => node.classList.remove(effect), 2400);
          }
          if (node === selectedTarget) showTargetDetail(node);
          freshTargets.delete(node.dataset.targetId);
        });
        freshTargets.forEach((node) => canvas.append(node.cloneNode(true)));
        const empty = canvas.querySelector(".wallboard-no-layout");
        if (empty) empty.hidden = Boolean(canvas.querySelector("[data-wallboard-target]"));
      });
      const freshLists = [...next.querySelectorAll("[data-wallboard-status-list]")];
      statusDialog?.querySelectorAll("[data-wallboard-status-list]").forEach((node) => copyContents(node, freshLists.find((item) => item.dataset.wallboardStatusList === node.dataset.wallboardStatusList)));
      const feed = eventsPanel?.querySelector(":scope > div");
      const freshFeed = nextBoard.querySelector("[data-wallboard-events] > div");
      const previousEvents = new Set([...(feed?.children || [])].map((node) => node.textContent));
      const feedScroll = feed?.scrollTop || 0;
      copyContents(feed, freshFeed);
      if (feed) {
        feed.scrollTop = feedScroll;
        [...feed.children].forEach((node) => {
          if (!previousEvents.has(node.textContent)) node.classList.add("is-new-event");
        });
      }
      applyTargetScales(sites.filter((node) => !node.hidden));
    };
    let lastInteraction = Date.now();
    ["pointermove", "pointerdown", "keydown"].forEach((name) => board.addEventListener(name, () => {
      lastInteraction = Date.now();
      board.classList.remove("is-idle");
    }, { passive: true }));
    const idleTimer = window.setInterval(() => {
      if (!board.isConnected) { window.clearInterval(idleTimer); return; }
      board.classList.toggle("is-idle", Date.now() - lastInteraction > 15_000);
    }, 3000);
    document.addEventListener("keydown", (event) => {
      if (!board.isConnected || event.key !== "Escape") return;
      const alert = document.querySelector("[data-critical-alert]");
      if (alert && !alert.hidden) {
        criticalAlerts?.close();
        return;
      }
      if (statusDialog && !statusDialog.hidden) {
        closeStatusDialog();
        return;
      }
      setActionsMenuOpen(false);
      close();
      if (rotationTimer || board.classList.contains("is-rotating")) stopRotation(false);
    });
    const fullscreenButton = document.querySelector("[data-wallboard-fullscreen]");
    const syncFullscreenButton = () => {
      const active = Boolean(document.fullscreenElement);
      if (!fullscreenButton) return;
      setExpandIcon(fullscreenButton, active);
      fullscreenButton.title = active ? "Выйти из полноэкранного режима" : "На весь экран";
      fullscreenButton.setAttribute("aria-label", fullscreenButton.title);
    };
    fullscreenButton?.addEventListener("click", async () => {
      if (document.fullscreenElement) await document.exitFullscreen?.();
      else await document.documentElement.requestFullscreen?.();
    });
    document.addEventListener("fullscreenchange", () => {
      syncFullscreenButton();
      if (!document.fullscreenElement && (rotationTimer || board.classList.contains("is-rotating"))) {
        stopRotation(false);
      }
    });
    syncFullscreenButton();
  };

  const enablePush = async () => {
    if (!pushSupported()) throw new Error("Push недоступен: требуется HTTPS и поддержка браузера");
    const permission = await Notification.requestPermission();
    if (permission !== "granted") throw new Error("Разрешение на Push-уведомления не предоставлено");
    const keyResponse = await fetch("/push/public-key", { credentials: "same-origin", cache: "no-store" });
    if (!keyResponse.ok) throw new Error("Не удалось получить ключ Push");
    const { public_key: publicKey } = await keyResponse.json();
    const registration = await navigator.serviceWorker.ready;
    let subscription = await registration.pushManager.getSubscription();
    if (!subscription) {
      subscription = await registration.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlBase64ToUint8Array(publicKey)
      });
    }
    const response = await fetch("/push/subscribe", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfHeaderToken() },
      body: JSON.stringify(pushSubscriptionPayload(subscription))
    });
    if (!response.ok) {
      let message = "Не удалось сохранить Push-подписку";
      try { message = (await response.json()).detail || message; } catch (_error) {}
      throw new Error(message);
    }
    await syncPushState();
    showToast("Push-уведомления включены");
  };

  const disablePush = async () => {
    if (!("serviceWorker" in navigator)) return;
    const registration = await navigator.serviceWorker.ready;
    const subscription = await registration.pushManager.getSubscription();
    if (subscription) {
      const response = await fetch("/push/unsubscribe", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfHeaderToken() },
        body: JSON.stringify({ endpoint: subscription.endpoint })
      });
      if (!response.ok) throw new Error("Не удалось удалить Push-подписку");
      await subscription.unsubscribe();
    }
    await syncPushState();
    showToast("Push-уведомления отключены на этом устройстве");
  };

  document.addEventListener("click", async (event) => {
    const enable = event.target.closest("[data-push-enable]");
    const disable = event.target.closest("[data-push-disable]");
    if (!enable && !disable) return;
    event.preventDefault();
    const button = enable || disable;
    button.disabled = true;
    try {
      if (enable) await enablePush();
      else await disablePush();
    } catch (error) {
      showToast(error.message || "Операция Push не выполнена", "error");
      await syncPushState();
    } finally {
      button.disabled = false;
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && document.body.classList.contains("chat-drawer-open")) setChatDrawerOpen(false);
  });

  const backToTop = document.querySelector("[data-back-to-top]");
  if (backToTop) {
    const syncBackToTop = () => { backToTop.hidden = window.scrollY < 480; };
    syncBackToTop();
    window.addEventListener("scroll", syncBackToTop, { passive: true });
    backToTop.addEventListener("click", () => {
      window.scrollTo({ top: 0, behavior: "smooth" });
    });
  }

  if ("serviceWorker" in navigator) {
    window.addEventListener("load", () => navigator.serviceWorker.register("/service-worker.js"));
  }
  reinitializeDynamicPage();
})();
