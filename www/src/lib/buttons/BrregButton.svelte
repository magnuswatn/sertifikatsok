<script>
    export let orgnr;

    import { onMount, onDestroy } from "svelte";

    onMount(() => {
        window.M.Tooltip.init(button, {});
    });
    onDestroy(() => {
        window.M.Tooltip.getInstance(button).destroy();
    });

    let button;
</script>

<a
    bind:this={button}
    class="btn-floating btn-small waves-effect waves-light red tooltipped hoverable"
    data-position="top"
    data-tooltip="Slå opp bedriften i Brønnøysundregistrene"
    href="https://w2.brreg.no/enhet/sok/detalj.jsp?orgnr={orgnr}"
    target="_blank"
    rel="noreferrer"
>
    <i class="material-icons">business</i>
</a>
