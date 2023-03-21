<script>
    export let cert_set;

    import { onMount } from "svelte";
    import buypassLogo from "../assets/buypass.svg";
    import commfidesLogo from "../assets/commfides.svg";
    import CertCard from "./CertCard.svelte";

    import { getNorwegianDate, getStatusBadgeColor } from "./utils";

    import BrregButton from "./buttons/BrregButton.svelte";
    import LdapButton from "./buttons/LdapButton.svelte";
    import FeilformatertNotification from "./notifications/FeilformatertNotification.svelte";
    import RevokertNotification from "./notifications/RevokertNotification.svelte";
    import Seid2Notification from "./notifications/Seid2Notification.svelte";
    import UkjentCertTypeNotification from "./notifications/UkjentCertTypeNotification.svelte";
    import UnderenhetNotification from "./notifications/UnderenhetNotification.svelte";
    import NotASmartCardNotification from "./notifications/NotASmartCardNotification.svelte";

    let collapsible;

    let opened = false;

    onMount(() => {
        window.M.Collapsible.init(collapsible, {});
        openIfHashMatch(true);
    });

    const openBody = () => {
        opened = true;
    };

    function openIfHashMatch(scroll) {
        cert_set.certificates.forEach((cert) => {
            let thumbprint = `${cert.info["Avtrykk (SHA-1)"]}`;
            if (window.location.hash.toLowerCase() === `#${thumbprint}`) {
                if (scroll) {
                    collapsible.scrollIntoView();
                }

                openBody();
                window.M.Collapsible.getInstance(collapsible).open();
            }
        });
    }
</script>

<svelte:window on:hashchange={() => openIfHashMatch(false)} />

<ul class="collapsible" data-collapsible="expandable" bind:this={collapsible}>
    <li>
        <div
            class="collapsible-header"
            on:click={openBody}
            on:keydown={(e) => {
                if (e.key == "Enter") openBody();
            }}
        >
            <div class="row">
                <div class="col s3">
                    Utstedt {getNorwegianDate(cert_set.valid_from)}
                </div>
                <div class="col s5">
                    {cert_set.subject}
                </div>
                <div class="col s2">
                    <span
                        class="new badge {getStatusBadgeColor(cert_set.status)}"
                        data-badge-caption={cert_set.status}
                    />
                </div>
                <div class="col s2">
                    <div class="right">
                        {#if cert_set.issuer === "Buypass"}
                            <img
                                src={buypassLogo}
                                alt="Buypass-logo"
                                style="width: 80px;"
                            />
                        {:else}
                            <img
                                src={commfidesLogo}
                                alt="Commfides-logo"
                                style="width: 80px;"
                            />
                        {/if}
                    </div>
                </div>
            </div>
        </div>

        <div class="collapsible-body">
            {#if opened}
                <span>
                    {#if cert_set.status === "Revokert"}
                        <RevokertNotification />
                    {/if}
                    {#if cert_set.notices.includes("ukjent")}
                        <UkjentCertTypeNotification />
                    {/if}
                    {#if cert_set.notices.includes("seid2")}
                        <Seid2Notification />
                    {/if}
                    {#if cert_set.notices.includes("underenhet")}
                        <UnderenhetNotification />
                    {/if}
                    {#if cert_set.notices.includes("feilformatert")}
                        <FeilformatertNotification />
                    {/if}
                    {#if cert_set.notices.includes("not_a_smartcard")}
                        <NotASmartCardNotification />
                    {/if}
                    <br />
                    <h6 class="center-align">
                        Dette settet er gyldig til {getNorwegianDate(
                            cert_set.valid_to,
                            true
                        )}
                    </h6>
                    <br />
                    <div class="row">
                        {#each cert_set.certificates as cert}
                            <CertCard {cert} />
                        {/each}
                    </div>
                    <div>
                        <div class="divider" />
                        <br />
                        <div class="right-align">
                            {#if cert_set.org_number}
                                <BrregButton orgnr={cert_set.org_number} />
                            {/if}
                            {#if cert_set.ldap}
                                <LdapButton ldap_url={cert_set.ldap} />
                            {/if}
                        </div>
                    </div>
                </span>
            {/if}
        </div>
    </li>
</ul>

<style>
    .collapsible-header {
        display: block;
    }
</style>
