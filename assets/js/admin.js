jQuery(document).ready(function ($) {
  // Register cron manually
  $('.pmip-register-cron input[type="submit"]').on("click", function (e) {
    e.preventDefault(); // Prevent accidental form submission

    if (!confirm(pmipAdmin.i18n.confirmCron)) return;

    let $button = $(this);
    $button.prop("disabled", true);

    $.post(pmipAdmin.ajaxUrl, {
      action: "pmip_register_cron",
      nonce: pmipAdmin.nonce,
    })
      .done((response) => {
        alert(response.data.message || pmipAdmin.i18n.error);
        if (response.success) {
          $(".pmip-register-cron")
            .fadeTo(300, 0)
            .slideUp(300, function () {
              $(this).remove();
            });
        } else {
          $button.prop("disabled", false);
        }
      })
      .fail(() => {
        alert(pmipAdmin.i18n.error);
        $button.prop("disabled", false);
      });
  });
  // Show API token instructions
  $(".pmip-show-token-instructions").on("click", function (e) {
    e.preventDefault();
    $("#pmip-token-instructions").fadeIn(300);
    $("body").addClass("pmip-modal-open");
  });

  // Close button functionality
  $("#pmip-close").on("click", function () {
    $("#pmip-token-instructions").fadeOut(300);
    $("body").removeClass("pmip-modal-open");
  });

  // Close modal when clicking outside the content box
  $("#pmip-token-instructions").on("click", function (e) {
    if ($(e.target).is("#pmip-token-instructions")) {
      $("#pmip-token-instructions").fadeOut(300);
      $("body").removeClass("pmip-modal-open");
    }
  });

  // Block IP
  $("#pmip-block-ip").on("click", function () {
    const ip = $("#pmip-ip-input").val().trim();
    if (!ip) {
      alert(pmipAdmin.i18n.enterIp);
      return;
    }

    if (!confirm(pmipAdmin.i18n.confirmBlock)) {
      return;
    }

    $.ajax({
      url: pmipAdmin.ajaxUrl,
      type: "POST",
      data: {
        action: "pmip_block_ip",
        nonce: pmipAdmin.nonce,
        ip: ip,
      },
      beforeSend: function () {
        $("#pmip-block-ip").prop("disabled", true);
      },
      success: function (response) {
        if (response.success) {
          alert(response.data.message);
          $("#pmip-ip-input").val("");
          location.reload();
        } else {
          alert(response.data.message || pmipAdmin.i18n.error);
        }
      },
      error: function () {
        alert(pmipAdmin.i18n.error);
      },
      complete: function () {
        $("#pmip-block-ip").prop("disabled", false);
      },
    });
  });

  // Unblock IP
  $("#pmip-unblock-ip").on("click", function () {
    const ip = $("#pmip-ip-input").val().trim();
    if (!ip) {
      alert(pmipAdmin.i18n.enterIp);
      return;
    }

    if (!confirm(pmipAdmin.i18n.confirmUnblock)) {
      return;
    }

    $.ajax({
      url: pmipAdmin.ajaxUrl,
      type: "POST",
      data: {
        action: "pmip_unblock_ip",
        nonce: pmipAdmin.nonce,
        ip: ip,
      },
      beforeSend: function () {
        $("#pmip-unblock-ip").prop("disabled", true);
      },
      success: function (response) {
        if (response.success) {
          alert(response.data.message);
          $("#pmip-ip-input").val("");
          location.reload();
        } else {
          alert(response.data.message || pmipAdmin.i18n.error);
        }
      },
      error: function () {
        alert(pmipAdmin.i18n.error);
      },
      complete: function () {
        $("#pmip-unblock-ip").prop("disabled", false);
      },
    });
  });

  // Filter logs
  $("#pmip-log-level").on("change", function () {
    const level = $(this).val();
    if (level) {
      $(".pmip-log-entries tr").hide();
      $(".pmip-log-entries tr:first").show();
      $(".pmip-log-entries tr")
        .filter(function () {
          return $(this).find("td:eq(1)").text().toLowerCase() === level;
        })
        .show();
    } else {
      $(".pmip-log-entries tr").show();
    }
  });

  // Export logs
  $("#pmip-export-logs").on("click", function () {
    window.location.href =
      pmipAdmin.ajaxUrl + "?action=pmip_export_logs&nonce=" + pmipAdmin.nonce;
  });

  // Validate IP input
  $("#pmip-ip-input").on("input", function () {
    const ip = $(this).val().trim();
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;

    if (ip && !ipv4Regex.test(ip) && !ipv6Regex.test(ip)) {
      $(this).addClass("error");
    } else {
      $(this).removeClass("error");
    }
  });

  // Sync with Wordfence
  $("#pmip-sync-wordfence").on("click", function () {
    if (!confirm(pmipAdmin.i18n.confirmSync)) {
      return;
    }

    $.ajax({
      url: pmipAdmin.ajaxUrl,
      type: "POST",
      data: {
        action: "pmip_sync_wordfence",
        nonce: pmipAdmin.nonce,
      },
      beforeSend: function () {
        $("#pmip-sync-wordfence").prop("disabled", true);
      },
      success: function (response) {
        if (response.success) {
          alert(response.data.message);
          location.reload();
        } else {
          alert(response.data.message || pmipAdmin.i18n.error);
        }
      },
      error: function () {
        alert(pmipAdmin.i18n.error);
      },
      complete: function () {
        $("#pmip-sync-wordfence").prop("disabled", false);
      },
    });
  });

  // Toggle token visibility
  $("#pmip-toggle-token-visibility").on("click", function () {
    const $input = $("#pmip_master_token");
    const $icon = $(this).find(".dashicons");
    if ($input.attr("type") === "password") {
      $input.attr("type", "text");
      $icon.removeClass("dashicons-visibility").addClass("dashicons-hidden");
    } else {
      $input.attr("type", "password");
      $icon.removeClass("dashicons-hidden").addClass("dashicons-visibility");
    }
  });

  // Toggle connection details
  $("#pmip-view-details-toggle").on("click", function (e) {
    e.preventDefault();
    const $details = $("#pmip-connection-details");
    const $link = $(this);
    if ($details.is(":visible")) {
      $details.slideUp();
      $link.text($link.data("show-text") || "View Details");
    } else {
      $details.slideDown();
      $link.text($link.data("hide-text") || "Hide Details");
    }
  });

  // Toggle advanced/manual config
  $("#pmip-advanced-config-toggle").on("click", function (e) {
    e.preventDefault();
    const $section = $(".pmip-manual-config-section");
    const $config = $("#pmip-manual-config");
    const $link = $(this);
    if ($config.is(":visible")) {
      $config.slideUp();
      $section.removeClass("open");
    } else {
      $config.slideDown();
      $section.addClass("open");
    }
  });

  // Zone select change handler - enable/disable button
  $("#pmip_zone_select").on("change", function () {
    const $button = $("#pmip-select-zone-btn");
    if ($(this).val()) {
      $button.prop("disabled", false);
    } else {
      $button.prop("disabled", true);
    }
  });

  // Test Connection button
  $("#pmip-test-connection").on("click", function () {
    const $button = $(this);
    const originalText = $button.text();
    $button.prop("disabled", true).text("Testing...");

    $.ajax({
      url: pmipAdmin.ajaxUrl,
      type: "POST",
      data: {
        action: "pmip_test_connection",
        nonce: pmipAdmin.nonce,
      },
      success: function (response) {
        if (response.success) {
          alert(response.data.message || "Connection test successful!");
          location.reload();
        } else {
          alert(response.data.message || "Connection test failed. Please check your configuration.");
        }
      },
      error: function () {
        alert("Error testing connection. Please try again.");
      },
      complete: function () {
        $button.prop("disabled", false).text(originalText);
      },
    });
  });

  // Reconnect button - scrolls to setup flow (which should be visible for unverified connections)
  $("#pmip-reconnect-btn").on("click", function () {
    // Scroll to the setup flow section
    const $setupFlow = $(".pmip-setup-flow");
    if ($setupFlow.length && $setupFlow.is(":visible")) {
      $("html, body").animate(
        {
          scrollTop: $setupFlow.offset().top - 50,
        },
        500
      );
    } else {
      // If setup flow is hidden, show advanced config and scroll there
      $("#pmip-advanced-config-toggle").trigger("click");
      setTimeout(function () {
        $("html, body").animate(
          {
            scrollTop: $(".pmip-cloudflare-setup-card").offset().top - 50,
          },
          500
        );
      }, 300);
    }
  });

  // Reset Cloudflare Settings button
  $("#pmip-reset-cloudflare").on("click", function () {
    if (
      !confirm(
        "Are you sure you want to reset all Cloudflare connection settings? This will clear your API token, zone ID, ruleset ID, and rule ID. You will need to reconnect."
      )
    ) {
      return;
    }

    const $button = $(this);
    const originalText = $button.text();
    $button.prop("disabled", true).text("Resetting...");

    $.ajax({
      url: pmipAdmin.ajaxUrl,
      type: "POST",
      data: {
        action: "pmip_reset_cloudflare",
        nonce: pmipAdmin.nonce,
      },
      success: function (response) {
        if (response.success) {
          alert(response.data.message || "Settings reset successfully!");
          location.reload();
        } else {
          alert(response.data.message || "Failed to reset settings. Please try again.");
          $button.prop("disabled", false).text(originalText);
        }
      },
      error: function () {
        alert("Error resetting settings. Please try again.");
        $button.prop("disabled", false).text(originalText);
      },
    });
  });

  // Auto-connect to Cloudflare
  $("#pmip-auto-connect-btn").on("click", function () {
    const masterToken = $("#pmip_master_token").val().trim();
    const $button = $(this);
    const $status = $("#pmip-auto-connect-status");
    const $message = $("#pmip-auto-connect-message");
    const $zoneSelection = $("#pmip-zone-selection");
    const $zoneSelect = $("#pmip_zone_select");

    if (!masterToken) {
      $message.html(
        '<div class="notice notice-error"><p>Please enter your master token.</p></div>'
      );
      return;
    }

    $button.prop("disabled", true);
    $status.html(
      '<span class="spinner is-active" style="float: none; margin: 0;"></span> Connecting...'
    );
    $message.html("");
    $zoneSelection.hide();

    $.ajax({
      url: pmipAdmin.ajaxUrl,
      type: "POST",
      data: {
        action: "pmip_auto_connect",
        nonce: pmipAdmin.nonce,
        master_token: masterToken,
      },
      success: function (response) {
        if (response.success) {
          $status.html('<span style="color: green;">✓ Connected!</span>');
          $message.html(
            '<div class="notice notice-success inline"><p><strong>Success!</strong> ' +
              response.data.message +
              "</p></div>"
          );

          // Populate zone selection dropdown
          if (response.data.zones && response.data.zones.length > 0) {
            $zoneSelect
              .empty()
              .append('<option value="">-- Please select a zone --</option>');
            response.data.zones.forEach(function (zone) {
              $zoneSelect.append(
                '<option value="' +
                  zone.id +
                  '">' +
                  zone.name +
                  " (" +
                  zone.id +
                  ")</option>"
              );
            });
            // Show step 2
            $("#pmip-step-2").slideDown();
            // Disable zone select button initially
            $("#pmip-select-zone-btn").prop("disabled", true);
          }
        } else {
          $status.html("");
          $message.html(
            '<div class="notice notice-error inline"><p><strong>Error:</strong> ' +
              (response.data.message || pmipAdmin.i18n.error) +
              "</p></div>"
          );
          $button.prop("disabled", false);
        }
      },
      error: function () {
        $status.html("");
        $message.html(
          '<div class="notice notice-error"><p><strong>Error:</strong> ' +
            pmipAdmin.i18n.error +
            "</p></div>"
        );
        $button.prop("disabled", false);
      },
    });
  });

  // Zone selection and rule creation
  $("#pmip-select-zone-btn").on("click", function () {
    const zoneId = $("#pmip_zone_select").val();
    const $button = $(this);
    const $status = $("#pmip-zone-selection-status");
    const $message = $("#pmip-zone-selection-message");
    const $zoneSelect = $("#pmip_zone_select");

    if (!zoneId) {
      $message.html(
        '<div class="notice notice-error"><p>Please select a zone.</p></div>'
      );
      return;
    }

    $button.prop("disabled", true);
    $zoneSelect.prop("disabled", true);
    $status.html(
      '<span class="spinner is-active" style="float: none; margin: 0;"></span> Creating rule...'
    );
    $message.html("");

    $.ajax({
      url: pmipAdmin.ajaxUrl,
      type: "POST",
      data: {
        action: "pmip_select_zone",
        nonce: pmipAdmin.nonce,
        zone_id: zoneId,
      },
      success: function (response) {
        if (response.success) {
          $status.html('<span style="color: green;">✓ Rule Created!</span>');
          $message.html(
            '<div class="notice notice-success inline"><p><strong>Success!</strong> ' +
              response.data.message +
              "</p></div>"
          );
          setTimeout(function () {
            location.reload();
          }, 2000);
        } else {
          $status.html("");
          $message.html(
            '<div class="notice notice-error inline"><p><strong>Error:</strong> ' +
              (response.data.message || pmipAdmin.i18n.error) +
              "</p></div>"
          );
          $button.prop("disabled", false);
          $zoneSelect.prop("disabled", false);
        }
      },
      error: function () {
        $status.html("");
        $message.html(
          '<div class="notice notice-error inline"><p><strong>Error:</strong> ' +
            pmipAdmin.i18n.error +
            "</p></div>"
        );
        $button.prop("disabled", false);
        $zoneSelect.prop("disabled", false);
      },
    });
  });

  // Check if user is already subscribed
  if (pmipAdmin.isSubscribed) {
    $(".pmip-newsletter-form").hide();
    $(".pmip-newsletter").append(
      '<div class="pmip-newsletter-success">' +
        "<p>You are already subscribed!</p>" +
        "</div>"
    );
    return;
  }

  // Newsletter subscription
  $(".pmip-newsletter-form").on("submit", function (e) {
    e.preventDefault();
    const email = $(this).find('input[type="email"]').val();
    const $message = $(".pmip-newsletter-message");
    const $submitButton = $(this).find("button");
    const $form = $(this);
    const $newsletter = $(".pmip-newsletter");

    $.ajax({
      url: "https://polarmass.com/wp-json/pmip/v1/newsletter/signup",
      type: "POST",
      contentType: "application/json",
      data: JSON.stringify({ email: email }),
      beforeSend: function () {
        $submitButton.prop("disabled", true);
        $form.css("opacity", "0.5");
      },
      success: function (response) {
        if (response.success) {
          $form.fadeOut(300, function () {
            const successMessage = $(
              '<div class="pmip-newsletter-success">' +
                "<p>Thank you for subscribing to our newsletter!</p>" +
                "</div>"
            ).hide();
            $(this).after(successMessage);
            successMessage.fadeIn(300);
          });

          // Update option via AJAX
          $.ajax({
            url: pmipAdmin.ajaxUrl,
            type: "POST",
            data: {
              action: "pmip_update_newsletter_status",
              nonce: pmipAdmin.nonce,
            },
          });
        } else {
          $message
            .removeClass("success")
            .addClass("error")
            .text(response.data.message)
            .fadeIn();
        }
      },
      error: function () {
        $message
          .removeClass("success")
          .addClass("error")
          .text(pmipAdmin.i18n.error)
          .fadeIn();
      },
      complete: function () {
        $submitButton.prop("disabled", false);
        $form.css("opacity", "1");
        setTimeout(function () {
          $message.fadeOut();
        }, 5000);
      },
    });
  });

  // Tabbed UI & Lightbox JS (for custom rules section only)
  // Tabbed UI for custom rules
  const tabs = document.querySelectorAll(".pmip-tabs .pmip-tab");
  const tabContents = document.querySelectorAll(".pmip-tab-content");
  tabs.forEach((tab) => {
    tab.addEventListener("click", function () {
      tabs.forEach((t) => t.classList.remove("active"));
      tabContents.forEach((tc) => tc.classList.remove("active"));
      this.classList.add("active");
      const tabContent = document.querySelector(
        ".pmip-tab-content-" + this.dataset.tab
      );
      if (tabContent) {
        tabContent.classList.add("active");
      }
    });
  });

  // Lightbox
  const overlay = document.createElement("div");
  overlay.className = "pmip-lightbox-overlay";
  overlay.innerHTML =
    '<span class="pmip-lightbox-close">&times;</span><img src="" alt="Preview">';
  document.body.appendChild(overlay);

  document.querySelectorAll(".pmip-lightbox").forEach((link) => {
    link.addEventListener("click", function (e) {
      e.preventDefault();
      overlay.querySelector("img").src = this.href;
      overlay.classList.add("active");
    });
  });

  if (overlay.querySelector(".pmip-lightbox-close")) {
    overlay.querySelector(".pmip-lightbox-close").onclick = function () {
      overlay.classList.remove("active");
      overlay.querySelector("img").src = "";
    };
  }

  overlay.onclick = function (e) {
    if (e.target === overlay) {
      overlay.classList.remove("active");
      overlay.querySelector("img").src = "";
    }
  };

  // IP List Management
  const $useIpList = $("#pmip_use_ip_list");
  const $ipListInfo = $("#pmip-ip-list-info");
  const $listsInfo = $("#pmip-lists-info");
  const $refreshLists = $("#pmip-refresh-lists");
  const $createList = $("#pmip-create-list");

  // Toggle IP list info visibility
  function toggleIpListInfo() {
    if ($useIpList.is(":checked")) {
      $ipListInfo.show();
      loadIpLists();
    } else {
      $ipListInfo.hide();
    }
  }

  // Load IP lists information
  function loadIpLists() {
    $listsInfo.html(
      '<p class="description"><span class="spinner is-active" style="float: none; margin: 0 10px 0 0;"></span>Loading IP lists information...</p>'
    );

    $.ajax({
      url: pmipAdmin.ajaxUrl,
      type: "POST",
      data: {
        action: "pmip_get_ip_lists",
        nonce: pmipAdmin.nonce,
      },
      success: function (response) {
        if (response.success && response.data) {
          displayListsInfo(response.data);
        } else {
          $listsInfo.html(
            '<p class="description" style="color: #d63638;">' +
              (response.data?.message || "Failed to load IP lists") +
              "</p>"
          );
        }
      },
      error: function () {
        $listsInfo.html(
          '<p class="description" style="color: #d63638;">Error loading IP lists. Please try again.</p>'
        );
      },
    });
  }

  // Display lists information
  function displayListsInfo(data) {
    let html = "";
    const totalLists = data.total_lists || 0;
    const pluginList = data.plugin_list;

    html +=
      '<p class="description"><strong>Total IP Lists:</strong> ' +
      totalLists +
      "</p>";

    if (pluginList) {
      html +=
        '<div style="margin-top: 10px; padding: 10px; background: #f0f6fc; border-left: 4px solid #2271b1; border-radius: 4px;">';
      html +=
        '<p><strong>Plugin IP List Found:</strong> ' + pluginList.name + "</p>";
      html +=
        '<p><strong>Items:</strong> ' +
        (pluginList.num_items || 0) +
        "</p>";
      html +=
        '<p><strong>Referenced by:</strong> ' +
        (pluginList.num_referencing_filters || 0) +
        " filter(s)</p>";
      if (pluginList.description) {
        html +=
          '<p><strong>Description:</strong> ' +
          pluginList.description +
          "</p>";
      }
      html += "</div>";
      $createList.hide();
    } else {
      html +=
        '<div style="margin-top: 10px; padding: 10px; background: #fff3cd; border-left: 4px solid #ffb900; border-radius: 4px;">';
      html +=
        '<p><strong>No IP list found for this plugin.</strong> Click "Create IP List" to create one.</p>';
      html += "</div>";
      $createList.show();
    }

    $listsInfo.html(html);
  }

  // Toggle change handler
  $useIpList.on("change", function () {
    toggleIpListInfo();
  });

  // Initial load
  if ($useIpList.is(":checked")) {
    toggleIpListInfo();
  }

  // Refresh lists button
  $refreshLists.on("click", function () {
    loadIpLists();
  });

  // Create list button
  $createList.on("click", function () {
    const $button = $(this);
    $button.prop("disabled", true).text("Creating...");

    $.ajax({
      url: pmipAdmin.ajaxUrl,
      type: "POST",
      data: {
        action: "pmip_create_ip_list",
        nonce: pmipAdmin.nonce,
      },
      success: function (response) {
        if (response.success) {
          alert(response.data.message || "IP list created successfully!");
          loadIpLists();
        } else {
          alert(
            response.data?.message || "Failed to create IP list. Please try again."
          );
          $button.prop("disabled", false).text("Create IP List");
        }
      },
      error: function () {
        alert("Error creating IP list. Please try again.");
        $button.prop("disabled", false).text("Create IP List");
      },
    });
  });
});
