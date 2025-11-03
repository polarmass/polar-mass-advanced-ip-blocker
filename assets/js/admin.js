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

  // Tab switching
  $(".pmip-tab-header").on("click", function () {
    const targetTab = $(this).data("tab");

    // Update tab headers
    $(".pmip-tab-header").removeClass("active").css({
      "border-bottom-color": "transparent",
      color: "#646970",
    });
    $(this).addClass("active").css({
      "border-bottom-color": "#2271b1",
      color: "#2271b1",
    });

    // Update tab content
    $(".pmip-tab-content").hide();
    $("#pmip-tab-" + targetTab).show();
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
            '<div class="notice notice-success"><p><strong>Success!</strong> ' +
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
            $zoneSelection.show();
          }
        } else {
          $status.html("");
          $message.html(
            '<div class="notice notice-error"><p><strong>Error:</strong> ' +
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

    if (!zoneId) {
      $message.html(
        '<div class="notice notice-error"><p>Please select a zone.</p></div>'
      );
      return;
    }

    $button.prop("disabled", true);
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
            '<div class="notice notice-success"><p><strong>Success!</strong> ' +
              response.data.message +
              "</p></div>"
          );
          setTimeout(function () {
            location.reload();
          }, 2000);
        } else {
          $status.html("");
          $message.html(
            '<div class="notice notice-error"><p><strong>Error:</strong> ' +
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
});
