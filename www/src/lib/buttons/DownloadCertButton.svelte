<script>
    export let base64cert;
    export let thumbprint;

    import { downloadCert } from "../utils";
    import MaterializeButton from "./MaterializeButton.svelte";
</script>

<MaterializeButton
    data_position="top"
    data_tooltip="Last ned dette sertifikatet"
    on:click={() => downloadCert(base64cert, thumbprint)}
>
    <i class="material-icons">file_download</i>
</MaterializeButton>
