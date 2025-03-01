
<a name="0x1_ParallelExecutionConfig"></a>

# Module `0x1::ParallelExecutionConfig`

This module defines structs and methods to initialize VM configurations,
including different costs of running the VM.


-  [Struct `ParallelExecutionConfig`](#0x1_ParallelExecutionConfig_ParallelExecutionConfig)
-  [Function `initialize_parallel_execution`](#0x1_ParallelExecutionConfig_initialize_parallel_execution)
-  [Function `enable_parallel_execution_with_config`](#0x1_ParallelExecutionConfig_enable_parallel_execution_with_config)
-  [Function `disable_parallel_execution`](#0x1_ParallelExecutionConfig_disable_parallel_execution)
-  [Module Specification](#@Module_Specification_0)
    -  [Access Control](#@Access_Control_1)


<pre><code><b>use</b> <a href="../../../../../../../DPN/releases/artifacts/current/build/MoveStdlib/docs/Option.md#0x1_Option">0x1::Option</a>;
<b>use</b> <a href="Reconfiguration.md#0x1_Reconfiguration">0x1::Reconfiguration</a>;
<b>use</b> <a href="Roles.md#0x1_Roles">0x1::Roles</a>;
<b>use</b> <a href="Timestamp.md#0x1_Timestamp">0x1::Timestamp</a>;
</code></pre>



<a name="0x1_ParallelExecutionConfig_ParallelExecutionConfig"></a>

## Struct `ParallelExecutionConfig`

The struct to hold the read/write set analysis result for the whole Diem Framework.


<pre><code><b>struct</b> <a href="ParallelExecutionConfig.md#0x1_ParallelExecutionConfig">ParallelExecutionConfig</a> <b>has</b> <b>copy</b>, drop, store
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>read_write_analysis_result: <a href="../../../../../../../DPN/releases/artifacts/current/build/MoveStdlib/docs/Option.md#0x1_Option_Option">Option::Option</a>&lt;vector&lt;u8&gt;&gt;</code>
</dt>
<dd>
 Serialized analysis result for the Diem Framework.
 If this payload is not None, DiemVM will use this config to execute transactions in parallel.
</dd>
</dl>


</details>

<a name="0x1_ParallelExecutionConfig_initialize_parallel_execution"></a>

## Function `initialize_parallel_execution`

Enable parallel execution functionality of DiemVM by setting the read_write_set analysis result.


<pre><code><b>public</b> <b>fun</b> <a href="ParallelExecutionConfig.md#0x1_ParallelExecutionConfig_initialize_parallel_execution">initialize_parallel_execution</a>(dr_account: &signer)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="ParallelExecutionConfig.md#0x1_ParallelExecutionConfig_initialize_parallel_execution">initialize_parallel_execution</a>(
    dr_account: &signer,
) {
    // The permission "UpdateVMConfig" is granted <b>to</b> DiemRoot [[H11]][PERMISSION].
    <a href="Roles.md#0x1_Roles_assert_diem_root">Roles::assert_diem_root</a>(dr_account);
    <a href="Reconfiguration.md#0x1_Reconfiguration_publish_new_config">Reconfiguration::publish_new_config</a>(
        dr_account,
        <a href="ParallelExecutionConfig.md#0x1_ParallelExecutionConfig">ParallelExecutionConfig</a> {
            read_write_analysis_result: <a href="../../../../../../../DPN/releases/artifacts/current/build/MoveStdlib/docs/Option.md#0x1_Option_none">Option::none</a>(),
        },
    );
}
</code></pre>



</details>

<details>
<summary>Specification</summary>


Must abort if the signer does not have the DiemRoot role [[H11]][PERMISSION].


<pre><code><b>include</b> <a href="Roles.md#0x1_Roles_AbortsIfNotDiemRoot">Roles::AbortsIfNotDiemRoot</a>{account: dr_account};
<b>include</b> <a href="Reconfiguration.md#0x1_Reconfiguration_PublishNewConfigAbortsIf">Reconfiguration::PublishNewConfigAbortsIf</a>&lt;<a href="ParallelExecutionConfig.md#0x1_ParallelExecutionConfig">ParallelExecutionConfig</a>&gt;;
<b>include</b> <a href="Reconfiguration.md#0x1_Reconfiguration_PublishNewConfigEnsures">Reconfiguration::PublishNewConfigEnsures</a>&lt;<a href="ParallelExecutionConfig.md#0x1_ParallelExecutionConfig">ParallelExecutionConfig</a>&gt; {
    payload: <a href="ParallelExecutionConfig.md#0x1_ParallelExecutionConfig">ParallelExecutionConfig</a> {
        read_write_analysis_result: <a href="../../../../../../../DPN/releases/artifacts/current/build/MoveStdlib/docs/Option.md#0x1_Option_none">Option::none</a>(),
    }};
</code></pre>



</details>

<a name="0x1_ParallelExecutionConfig_enable_parallel_execution_with_config"></a>

## Function `enable_parallel_execution_with_config`



<pre><code><b>public</b> <b>fun</b> <a href="ParallelExecutionConfig.md#0x1_ParallelExecutionConfig_enable_parallel_execution_with_config">enable_parallel_execution_with_config</a>(dr_account: &signer, read_write_inference_result: vector&lt;u8&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="ParallelExecutionConfig.md#0x1_ParallelExecutionConfig_enable_parallel_execution_with_config">enable_parallel_execution_with_config</a>(
   dr_account: &signer,
   read_write_inference_result: vector&lt;u8&gt;,
) {
    <a href="Timestamp.md#0x1_Timestamp_assert_operating">Timestamp::assert_operating</a>();
    <a href="Roles.md#0x1_Roles_assert_diem_root">Roles::assert_diem_root</a>(dr_account);
    <a href="Reconfiguration.md#0x1_Reconfiguration_set">Reconfiguration::set</a>(dr_account, <a href="ParallelExecutionConfig.md#0x1_ParallelExecutionConfig">ParallelExecutionConfig</a> {
        read_write_analysis_result: <a href="../../../../../../../DPN/releases/artifacts/current/build/MoveStdlib/docs/Option.md#0x1_Option_some">Option::some</a>(read_write_inference_result),
    });
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="Timestamp.md#0x1_Timestamp_AbortsIfNotOperating">Timestamp::AbortsIfNotOperating</a>;
</code></pre>


No one can update VMConfig except for the Diem Root account [[H11]][PERMISSION].


<pre><code><b>include</b> <a href="Roles.md#0x1_Roles_AbortsIfNotDiemRoot">Roles::AbortsIfNotDiemRoot</a>{account: dr_account};
<b>include</b> <a href="Reconfiguration.md#0x1_Reconfiguration_SetAbortsIf">Reconfiguration::SetAbortsIf</a>&lt;<a href="ParallelExecutionConfig.md#0x1_ParallelExecutionConfig">ParallelExecutionConfig</a>&gt;{account: dr_account };
<b>ensures</b> <a href="Reconfiguration.md#0x1_Reconfiguration_spec_is_published">Reconfiguration::spec_is_published</a>&lt;<a href="ParallelExecutionConfig.md#0x1_ParallelExecutionConfig">ParallelExecutionConfig</a>&gt;();
<b>ensures</b> <b>old</b>(<a href="Reconfiguration.md#0x1_Reconfiguration_spec_has_config">Reconfiguration::spec_has_config</a>()) == <a href="Reconfiguration.md#0x1_Reconfiguration_spec_has_config">Reconfiguration::spec_has_config</a>();
</code></pre>



</details>

<a name="0x1_ParallelExecutionConfig_disable_parallel_execution"></a>

## Function `disable_parallel_execution`



<pre><code><b>public</b> <b>fun</b> <a href="ParallelExecutionConfig.md#0x1_ParallelExecutionConfig_disable_parallel_execution">disable_parallel_execution</a>(dr_account: &signer)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="ParallelExecutionConfig.md#0x1_ParallelExecutionConfig_disable_parallel_execution">disable_parallel_execution</a>(
   dr_account: &signer,
) {
    <a href="Timestamp.md#0x1_Timestamp_assert_operating">Timestamp::assert_operating</a>();
    <a href="Roles.md#0x1_Roles_assert_diem_root">Roles::assert_diem_root</a>(dr_account);
    <a href="Reconfiguration.md#0x1_Reconfiguration_set">Reconfiguration::set</a>(dr_account, <a href="ParallelExecutionConfig.md#0x1_ParallelExecutionConfig">ParallelExecutionConfig</a> {
        read_write_analysis_result: <a href="../../../../../../../DPN/releases/artifacts/current/build/MoveStdlib/docs/Option.md#0x1_Option_none">Option::none</a>(),
    });
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="Timestamp.md#0x1_Timestamp_AbortsIfNotOperating">Timestamp::AbortsIfNotOperating</a>;
</code></pre>


No one can update VMConfig except for the Diem Root account [[H11]][PERMISSION].


<pre><code><b>include</b> <a href="Roles.md#0x1_Roles_AbortsIfNotDiemRoot">Roles::AbortsIfNotDiemRoot</a>{account: dr_account};
<b>include</b> <a href="Reconfiguration.md#0x1_Reconfiguration_SetAbortsIf">Reconfiguration::SetAbortsIf</a>&lt;<a href="ParallelExecutionConfig.md#0x1_ParallelExecutionConfig">ParallelExecutionConfig</a>&gt;{account: dr_account };
<b>ensures</b> <a href="Reconfiguration.md#0x1_Reconfiguration_spec_is_published">Reconfiguration::spec_is_published</a>&lt;<a href="ParallelExecutionConfig.md#0x1_ParallelExecutionConfig">ParallelExecutionConfig</a>&gt;();
<b>ensures</b> <a href="Reconfiguration.md#0x1_Reconfiguration_get">Reconfiguration::get</a>&lt;<a href="ParallelExecutionConfig.md#0x1_ParallelExecutionConfig">ParallelExecutionConfig</a>&gt;() == <a href="ParallelExecutionConfig.md#0x1_ParallelExecutionConfig">ParallelExecutionConfig</a> {
    read_write_analysis_result: <a href="../../../../../../../DPN/releases/artifacts/current/build/MoveStdlib/docs/Option.md#0x1_Option_none">Option::none</a>(),
};
<b>ensures</b> <b>old</b>(<a href="Reconfiguration.md#0x1_Reconfiguration_spec_has_config">Reconfiguration::spec_has_config</a>()) == <a href="Reconfiguration.md#0x1_Reconfiguration_spec_has_config">Reconfiguration::spec_has_config</a>();
</code></pre>



</details>

<a name="@Module_Specification_0"></a>

## Module Specification



<a name="@Access_Control_1"></a>

### Access Control

The permission "UpdateParallelExecutionConfig" is granted to DiemRoot [[H11]][PERMISSION].


<pre><code><b>invariant</b> [suspendable] <b>forall</b> addr: <b>address</b>
    <b>where</b> <b>exists</b>&lt;<a href="Reconfiguration.md#0x1_Reconfiguration">Reconfiguration</a>&lt;<a href="ParallelExecutionConfig.md#0x1_ParallelExecutionConfig">ParallelExecutionConfig</a>&gt;&gt;(addr): addr == @DiemRoot;
<b>invariant</b> <b>update</b> [suspendable] <b>old</b>(<a href="Reconfiguration.md#0x1_Reconfiguration_spec_is_published">Reconfiguration::spec_is_published</a>&lt;<a href="ParallelExecutionConfig.md#0x1_ParallelExecutionConfig">ParallelExecutionConfig</a>&gt;())
    && <a href="Reconfiguration.md#0x1_Reconfiguration_spec_is_published">Reconfiguration::spec_is_published</a>&lt;<a href="ParallelExecutionConfig.md#0x1_ParallelExecutionConfig">ParallelExecutionConfig</a>&gt;()
    && <b>old</b>(<a href="Reconfiguration.md#0x1_Reconfiguration_get">Reconfiguration::get</a>&lt;<a href="ParallelExecutionConfig.md#0x1_ParallelExecutionConfig">ParallelExecutionConfig</a>&gt;()) != <a href="Reconfiguration.md#0x1_Reconfiguration_get">Reconfiguration::get</a>&lt;<a href="ParallelExecutionConfig.md#0x1_ParallelExecutionConfig">ParallelExecutionConfig</a>&gt;()
        ==&gt; <a href="Roles.md#0x1_Roles_spec_signed_by_diem_root_role">Roles::spec_signed_by_diem_root_role</a>();
</code></pre>


No one can update VMConfig except for the Diem Root account [[H11]][PERMISSION].


<a name="0x1_ParallelExecutionConfig_VMConfigRemainsSame"></a>


<pre><code><b>schema</b> <a href="ParallelExecutionConfig.md#0x1_ParallelExecutionConfig_VMConfigRemainsSame">VMConfigRemainsSame</a> {
    <b>ensures</b> <b>old</b>(<a href="Reconfiguration.md#0x1_Reconfiguration_spec_is_published">Reconfiguration::spec_is_published</a>&lt;<a href="ParallelExecutionConfig.md#0x1_ParallelExecutionConfig">ParallelExecutionConfig</a>&gt;()) ==&gt;
        <b>global</b>&lt;<a href="Reconfiguration.md#0x1_Reconfiguration">Reconfiguration</a>&lt;<a href="ParallelExecutionConfig.md#0x1_ParallelExecutionConfig">ParallelExecutionConfig</a>&gt;&gt;(@DiemRoot) ==
            <b>old</b>(<b>global</b>&lt;<a href="Reconfiguration.md#0x1_Reconfiguration">Reconfiguration</a>&lt;<a href="ParallelExecutionConfig.md#0x1_ParallelExecutionConfig">ParallelExecutionConfig</a>&gt;&gt;(@DiemRoot));
}
</code></pre>




<pre><code><b>apply</b> <a href="ParallelExecutionConfig.md#0x1_ParallelExecutionConfig_VMConfigRemainsSame">VMConfigRemainsSame</a> <b>to</b> * <b>except</b> enable_parallel_execution_with_config, disable_parallel_execution;
</code></pre>
