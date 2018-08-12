import React, { Component } from 'react';
import PropTypes from 'prop-types';
import M from 'materialize-css';

export class SertifikatsokCollapsible extends Component {
    constructor(props) {
        super(props);
        this.ref = React.createRef();
        this.state = {
            open: false,
        };
    }

    handleClick() {
        if (!(this.self)) {
            this.self = M.Collapsible.init(this.ref.current, { onCloseEnd: () => this.close() });
        }
        if (this.state.open) {
            this.self.close()
        } else {
            this.setState({
                open: !this.state.open,
            });
        }
    }

    handleKeyPress(e) {
        if (e.key === 'Enter') {
            this.handleClick();
        }
    }

    close() {
        this.setState({
            open: false,
        });
        this.self.destroy();
        this.self = null;
    }

    componentDidUpdate() {
        if (this.state.open) {
            this.self.open();
        }
    }

    componentWillUnmount() {
        this.self.destroy();
        this.self = null;
    }

    render() {
        if (this.state.open) {
            return (
                <ul ref={this.ref} className="collapsible" style={{ cursor: 'pointer' }}>
                    <li>
                        <div className="collapsible-header" tabIndex="0" onKeyDown={(e) => this.handleKeyPress(e)} onClick={() => this.handleClick()}>{this.props.header}</div>
                        <div className="collapsible-body">{this.props.body}</div>
                    </li>
                </ul>
            )
        } else {
            return (
                <ul ref={this.ref} className="collapsible" style={{ cursor: 'pointer' }}>
                    <li>
                        <div className="collapsible-header" tabIndex="0" onKeyDown={(e) => this.handleKeyPress(e)} onClick={() => this.handleClick()}>{this.props.header}</div>
                    </li>
                </ul>
            )
        }
    }
}

SertifikatsokCollapsible.propTypes = {
    body: PropTypes.object,
    header: PropTypes.object,
}
